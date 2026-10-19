#!/usr/bin/env python3
"""Launch Watch paid instant scan bot (runs in GitHub Actions; standard library + pycryptodome for the scanner).

Event mode (GitHub Actions):   python3 bot/paid_scan.py            (reads GITHUB_EVENT_NAME / GITHUB_EVENT_PATH)
Local dry runs (no GitHub writes, no ledger writes):
  python3 bot/paid_scan.py --check-tx <txid>                  # payment verdict only
  python3 bot/paid_scan.py --scan robinhood 0x... [--json-in f] # print the report comment Markdown

Payment rules: BTC only, to PAY_ADDR, >= the tier minimum (10% under list price allowed), >= 1 confirmation,
txid never used before (ledger/used-txids.json, committed to this repo). Mixer/CoinJoin-funded payments and
targets in the excluded hosting cluster are declined politely and flagged for a manual refund; nothing is auto-refunded.
"""
import argparse, datetime as dt, json, os, re, subprocess, sys, time, urllib.error, urllib.parse, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
LEDGER = os.path.join(ROOT, "ledger", "used-txids.json")
SCORER = os.path.join(ROOT, "scanner", "score.py")
CLUSTERS = os.path.join(ROOT, "scanner", "data", "clusters.json")
EXCLUDED = os.path.join(ROOT, "ledger", "excluded-targets.json")

PAY_ADDR = "bc1qk43phw0cl63a2pqxssnakwsnuxu0swwjvmm9r0"   # public receive address only; no keys anywhere in this repo
MAINTAINER = "invisiblemonsters"
FIXED_RATE_USD = 81771            # USD per BTC, fixed 2026-10-19 (mempool.space price that day). Prices below do not float.
SINGLE_SATS, SINGLE_MIN = 6100, 5490        # $5  -> 6,100 sats; accepted from 5,490 (10% tolerance)
PACK_SATS, PACK_MIN, PACK_MAX = 24500, 22050, 26950   # $20 pack of 5 scans; 10% tolerance either side
PACK_USES = 5
NOT_BEFORE_UTC = dt.datetime(2026, 10, 19, 7, 0, tzinfo=dt.timezone.utc)   # payments confirmed before launch are not claimable
EXCLUDED_IPS = {"187.127.98.242"}           # Pons hosting cluster: declined, manual refund
MEMPOOL = "https://mempool.space/api"
SITE = "https://invisiblemonsters.github.io/launch-watch/"
REVIEW_FORM = "https://github.com/invisiblemonsters/launch-watch/issues/new?template=request-review.yml"
CHAIN_OPTS = {"robinhood chain (chain id 4663)": "robinhood", "base (chain id 8453)": "base",
              "robinhood chain": "robinhood", "robinhood": "robinhood", "base": "base"}
CHAIN_NAME = {"robinhood": "Robinhood Chain", "base": "Base"}
ADDR_RX = re.compile(r"^0x[0-9a-fA-F]{40}$")
TXID_RX = re.compile(r"^[0-9a-fA-F]{64}$")
DONE_LABELS = {"scanned", "declined", "refund-due"}
RETRY_LABELS = {"awaiting-confirmation", "scan-error"}
UA = {"User-Agent": "launch-watch-scan/1.0"}
PT = dt.timezone(dt.timedelta(hours=-7), "PT")
DISCLAIMER = ("_Automated on-chain checks at the block shown, not an audit, not a guarantee and not financial advice. "
              "A risk signal is not evidence of wrongdoing by any team. On-chain state can change after this scan._")

# ------------------------------------------------------------------ HTTP helpers
def http_json(url, method="GET", data=None, headers=None, timeout=30, tries=3):
    h = dict(UA); h.update(headers or {})
    body = json.dumps(data).encode() if data is not None else None
    if body is not None: h["Content-Type"] = "application/json"
    last = None
    for i in range(tries):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, data=body, method=method, headers=h), timeout=timeout) as r:
                txt = r.read().decode("utf-8", "replace")
                return (json.loads(txt) if txt.strip() else None), r.status
        except urllib.error.HTTPError as e:
            if e.code in (400, 404, 410, 422): return {"_error": e.read().decode("utf-8", "replace")[:300]}, e.code
            last = e
        except Exception as e:
            last = e
        time.sleep(2 * (i + 1))
    raise RuntimeError(f"{method} {url} failed: {last}")

def mempool(path):
    d, code = http_json(MEMPOOL + path)
    return d, code

# ------------------------------------------------------------------ payment check
def coinjoin_like(tx):
    """Heuristic: >=5 inputs and >=5 outputs of one identical value (Wasabi/Whirlpool/JoinMarket shape)."""
    vals = {}
    for o in tx.get("vout", []):
        vals[o.get("value")] = vals.get(o.get("value"), 0) + 1
    return len(tx.get("vin", [])) >= 5 and max(vals.values() or [0]) >= 5

def check_payment(txid):
    """Return dict(verdict=ok|unconfirmed|invalid|mixer, reason, sats, tier, uses_allowed, confs, block_time)."""
    txid = (txid or "").strip().lower()
    if not TXID_RX.match(txid):
        return {"verdict": "invalid", "reason": "That is not a Bitcoin transaction ID (it must be 64 hexadecimal characters)."}
    tx, code = mempool(f"/tx/{txid}")
    if code == 404 or not isinstance(tx, dict) or "_error" in tx:
        return {"verdict": "invalid", "reason": "mempool.space does not know this transaction ID. Check it was broadcast on Bitcoin mainnet and copied in full."}
    sats = sum(o.get("value", 0) for o in tx.get("vout", []) if o.get("scriptpubkey_address") == PAY_ADDR)
    st = tx.get("status") or {}
    out = {"txid": txid, "sats": sats, "confs": 0, "block_time": st.get("block_time")}
    if sats <= 0:
        return {**out, "verdict": "invalid", "reason": f"This transaction does not pay the Launch Watch address `{PAY_ADDR}`."}
    if sats < SINGLE_MIN:
        return {**out, "verdict": "invalid", "underpaid": True,
                "reason": f"This transaction pays {sats:,} sats; the instant scan needs at least {SINGLE_MIN:,} sats ({SINGLE_SATS:,} sats list price)."}
    if sats > PACK_MAX:
        return {**out, "verdict": "invalid", "other_tier": True,
                "reason": f"This transaction pays {sats:,} sats, which matches a Verified badge or 24h review order, not an instant scan. It has not been used here; the maintainer will match it to your order."}
    tier, uses = ("pack", PACK_USES) if sats >= PACK_MIN else ("single", 1)
    out.update(tier=tier, uses_allowed=uses)
    # mixer / CoinJoin screen: the payment itself and its direct parents
    if coinjoin_like(tx):
        return {**out, "verdict": "mixer", "reason": "The payment transaction has a CoinJoin/mixer shape."}
    for p in sorted({v.get("txid") for v in tx.get("vin", []) if v.get("txid")})[:8]:
        ptx, pc = mempool(f"/tx/{p}")
        if isinstance(ptx, dict) and "_error" not in ptx and coinjoin_like(ptx):
            return {**out, "verdict": "mixer", "reason": "The payment is funded directly from a CoinJoin/mixer transaction."}
    if not st.get("confirmed"):
        return {**out, "verdict": "unconfirmed", "reason": "The payment is in the mempool but has 0 confirmations."}
    tip, _ = mempool("/blocks/tip/height")
    out["confs"] = int(tip) - int(st["block_height"]) + 1 if isinstance(tip, int) else 1
    if st.get("block_time") and dt.datetime.fromtimestamp(st["block_time"], dt.timezone.utc) < NOT_BEFORE_UTC:
        return {**out, "verdict": "invalid", "reason": "This payment was confirmed before instant scans were offered, so it belongs to an earlier order."}
    return {**out, "verdict": "ok", "reason": f"{sats:,} sats to {PAY_ADDR}, {out['confs']} confirmation(s)."}

# ------------------------------------------------------------------ ledger
def load_ledger():
    try: return json.load(open(LEDGER))
    except Exception: return {}

def save_ledger(led, msg):
    json.dump(led, open(LEDGER, "w"), indent=1, sort_keys=True); open(LEDGER, "a").write("\n")
    if os.environ.get("LWS_NO_GIT"): return
    for i in range(4):
        subprocess.run(["git", "add", LEDGER], cwd=ROOT, check=True)
        if subprocess.run(["git", "diff", "--cached", "--quiet"], cwd=ROOT).returncode == 0: return
        subprocess.run(["git", "commit", "-qm", msg], cwd=ROOT, check=True)
        if subprocess.run(["git", "push", "-q", "origin", "HEAD:main"], cwd=ROOT).returncode == 0: return
        subprocess.run(["git", "reset", "-q", "--soft", "HEAD~1"], cwd=ROOT)
        subprocess.run(["git", "stash", "-q"], cwd=ROOT); subprocess.run(["git", "pull", "-q", "--rebase", "origin", "main"], cwd=ROOT)
        fresh = load_ledger(); subprocess.run(["git", "stash", "drop", "-q"], cwd=ROOT)
        for k, v in led.items():
            if k not in fresh: fresh[k] = v
            else:
                have = {c["issue"] for c in fresh[k]["claims"]}
                fresh[k]["claims"] += [c for c in v["claims"] if c["issue"] not in have]
        led = fresh; json.dump(led, open(LEDGER, "w"), indent=1, sort_keys=True); open(LEDGER, "a").write("\n")
    raise RuntimeError("could not push ledger update")

def ledger_check(led, pay, issue_no, author):
    """(ok, reason) without changing the ledger. Same issue re-checks are allowed; packs stay with the first account."""
    e = led.get(pay["txid"])
    if e is None: return True, ""
    if any(c["issue"] == issue_no for c in e["claims"]): return True, ""
    if e["author"].lower() != author.lower():
        first = e["claims"][0]["issue"] if e["claims"] else "?"
        return False, f"This transaction ID was already used for #{first}. A payment can only be used by the GitHub account that first submitted it."
    live = [c for c in e["claims"] if c["status"] != "refund-due"]
    if len(live) >= e["uses_allowed"]:
        return False, f"All {e['uses_allowed']} scan(s) paid by this transaction have been used ({', '.join('#%s' % c['issue'] for c in live)})."
    return True, ""

def ledger_record(led, pay, issue_no, author, status="claimed"):
    e = led.setdefault(pay["txid"], {"sats": pay["sats"], "tier": pay.get("tier"), "uses_allowed": pay.get("uses_allowed", 0), "author": author, "claims": []})
    if not any(c["issue"] == issue_no for c in e["claims"]):
        e["claims"].append({"issue": issue_no, "status": status, "at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")})
    else:
        set_claim(e, issue_no, status)
    return e

def set_claim(e, issue_no, status):
    for c in e["claims"]:
        if c["issue"] == issue_no: c["status"] = status

# ------------------------------------------------------------------ GitHub
class GH:
    def __init__(self):
        self.repo = os.environ["GITHUB_REPOSITORY"]; self.tok = os.environ["GITHUB_TOKEN"]
        self.api = f"https://api.github.com/repos/{self.repo}"
    def call(self, path, method="GET", data=None):
        d, code = http_json(self.api + path, method, data, {"Authorization": f"Bearer {self.tok}", "Accept": "application/vnd.github+json",
                                                          "X-GitHub-Api-Version": "2022-11-28"})
        if code >= 400: raise RuntimeError(f"GitHub {method} {path}: HTTP {code} {d}")
        return d
    def comment(self, n, body): self.call(f"/issues/{n}/comments", "POST", {"body": body})
    def comments(self, n): return self.call(f"/issues/{n}/comments?per_page=100") or []
    def add_labels(self, n, labels): self.call(f"/issues/{n}/labels", "POST", {"labels": list(labels)})
    def remove_label(self, n, label):
        try: self.call(f"/issues/{n}/labels/{urllib.parse.quote(label)}", "DELETE")
        except Exception: pass
    def close(self, n, reason="completed"): self.call(f"/issues/{n}", "PATCH", {"state": "closed", "state_reason": reason})
    def issue(self, n): return self.call(f"/issues/{n}")
    def open_requests(self):
        """Open paid-scan issues the bot should look at: awaiting confirmation, scan errors, or never processed
        (an event run can be dropped when several queue up). Issues waiting for the requester to edit them are left alone."""
        out = []
        for page in range(1, 4):
            batch = self.call(f"/issues?state=open&labels=paid-scan&per_page=100&page={page}") or []
            out += batch
            if len(batch) < 100: break
        wait_for_edit = DONE_LABELS | {"needs-info", "payment-invalid", "needs-maintainer"}
        return [i for i in out if not ({l["name"] for l in i.get("labels", [])} & wait_for_edit)]

# ------------------------------------------------------------------ form parsing
def parse_form(body):
    f, cur = {}, None
    for line in (body or "").splitlines():
        m = re.match(r"^###\s+(.+?)\s*$", line)
        if m: cur = m.group(1).strip().lower(); f[cur] = []; continue
        if cur is not None: f[cur].append(line)
    f = {k: "\n".join(v).strip() for k, v in f.items()}
    get = lambda *keys: next((f[k] for k in f for key in keys if k.startswith(key)), "")
    val = lambda s: "" if s.strip() in ("_No response_", "None") else s.strip()
    return {"chain": val(get("chain")), "address": val(get("contract address")), "txid": val(get("btc transaction id", "btc txid")),
            "site": val(get("project website"))}

# ------------------------------------------------------------------ scanning + report
def excluded_target(chain, address):
    try: ex = json.load(open(EXCLUDED))
    except Exception: ex = {"targets": []}
    return f"{chain}:{address.lower()}" in {t["key"] for t in ex.get("targets", [])}

SITE_RX = re.compile(r"^https?://[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+/?$", re.I)
def clean_site(s):
    s = (s or "").strip().split()[0] if (s or "").strip() else ""
    if s and "://" not in s: s = "https://" + s
    s = s.split("#")[0].split("?")[0]
    s = re.sub(r"^(https?://[^/]+)/.*$", r"\1/", s)
    return s if SITE_RX.match(s) else None

def run_scan(chain, address, site=None):
    extra = ["--site", site] if site else []
    p = subprocess.run([sys.executable, SCORER, "--chain", chain, "--address", address, "--json", *extra], cwd=os.path.dirname(SCORER),
                       capture_output=True, text=True, timeout=1500)
    if p.returncode != 0: raise RuntimeError(f"scanner exit {p.returncode}: {p.stderr[-400:]}")
    return json.loads(p.stdout)

def in_excluded_cluster(r):
    if set(r.get("site_ips") or []) & EXCLUDED_IPS: return True
    try: cl = json.load(open(CLUSTERS))["clusters"]
    except Exception: cl = []
    doms = {m["domain"].lower() for c in cl if set(c["ips"]) & EXCLUDED_IPS for m in c.get("members", [])}
    host = urllib.parse.urlparse(r.get("site") or "").hostname or ""
    return host.lower().removeprefix("www.") in doms

SAFE_HOSTS = ("blockscout.com", "gopluslabs.io", "dexscreener.com", "geckoterminal.com", "dns.google", "rdap.org", "ipinfo.io",
              "sourcify.dev", "honeypot.is", "x.com", "twitter.com")
def md(s, n=420):
    s = str(s if s is not None else "")
    s = s.replace("\r", " ").replace("\n", " ").replace("|", "/").replace("`", "'").replace("<", "&lt;").replace(">", "&gt;")
    s = s.replace("@", "@\u200b").replace("[", "(").replace("]", ")")
    return s if len(s) <= n else s[:n - 1] + "…"
def md_link(u):
    u = str(u)
    host = urllib.parse.urlparse(u).hostname or ""
    if u.startswith("https://") and any(host == h or host.endswith("." + h) for h in SAFE_HOSTS) and not re.search(r"[\s()<>\[\]`]", u):
        return f"[{host.replace('www.', '')}]({u})"
    u = re.sub(r"[`\r\n|]", " ", u)
    return f"`{u if len(u) <= 80 else u[:79] + '…'}`"

STATUS = {"flag": "⚠️ risk signal", "pass": "✅ pass", "info": "ℹ️ info", "unknown": "❔ unknown"}
def report_md(r, pay=None, test=False, uses_left=None):
    c = CHAIN_NAME[r["chain"]]; tok = r.get("token") or {}; a = r["address"]
    name = md(tok.get("name") or (r.get("blockscout") or {}).get("name") or "Unnamed contract", 60)
    sym = md(tok.get("symbol") or "", 20)
    scanned = dt.datetime.fromisoformat(r["scanned_at_utc"].replace("Z", "+00:00")).astimezone(PT)
    expl = {"robinhood": "https://robinhoodchain.blockscout.com", "base": "https://base.blockscout.com"}[r["chain"]]
    L = ["<!-- lws:report -->"]
    if test: L += ["> **TEST MODE**: maintainer test issue; the payment check was skipped.", ""]
    L += [f"## Launch Watch instant scan: {name}{f' ({sym})' if sym else ''} on {c}", "",
          f"**Risk score: {r['score']}/100 · {r['band']} risk signals** (0-24 LOW, 25-49 MODERATE, 50-74 ELEVATED, 75-100 HIGH; higher = more signals)", "",
          f"- Address: [`{a}`]({expl}/address/{a})",
          f"- Scanned {scanned:%Y-%m-%d %H:%M} PT at block {r.get('block')} · {r['coverage']['run']} checks ran · {r['coverage']['unknown']} unknown · scanner v{md(r.get('version'))}", ""]
    tops = r.get("top_reasons") or []
    if tops:
        L += ["**Top signals**", ""] + [f"{i}. **{md(t['title'])}** (+{t['points']:g}, {t['status']}): {md(t['detail'])}" for i, t in enumerate(tops, 1)] + [""]
    else:
        L += ["No check added points.", ""]
    L += ["<details><summary>Every check (status, points, evidence)</summary>", "", "| Status | Pts | Check | Detail | Evidence |", "|---|---|---|---|---|"]
    for ch in r["checks"]:
        ev = " ".join(md_link(e) for e in (ch.get("evidence") or [])[:2]) or "-"
        L.append(f"| {STATUS.get(ch['status'], ch['status'])} | {('+%g' % ch['points']) if ch['points'] else '0'} | {md(ch['title'], 80)} | {md(ch['detail'], 300)} | {ev} |")
    L += ["", "\"unknown\" = the check could not run with free public data; it adds a small fixed weight so missing data never looks safe.",
          f"Rules and weights: [methodology]({SITE}methodology.html).", "", "</details>", ""]
    if pay:
        L.append(f"Payment: [`{pay['txid'][:12]}…`](https://mempool.space/tx/{pay['txid']}) · {pay['sats']:,} sats · {pay.get('confs', 1)} confirmation(s)"
                 + (f" · scan pack: {uses_left} of {PACK_USES} scans left (open new instant-scan issues with the same txid from this account)" if uses_left is not None else ""))
        L.append("")
    q = urllib.parse.urlencode({"title": f"[Review request] {tok.get('name') or 'project'} on {c}", "chain": c, "addresses": a,
                                "project": tok.get("name") or ""}, quote_via=urllib.parse.quote)
    L += ["**Want more than an automated scan?**",
          f"- [Launch Watch Verified, $50](https://invisiblemonsters.github.io/launch-watch/get-reviewed.html): a person re-checks source and live owner/admin/roles; dated badge (LOW-band launches).",
          f"- [24-hour manual review, $150]({REVIEW_FORM}&{q}): written findings with evidence. Sensitive findings are shared privately, never in public issues.", "",
          DISCLAIMER]
    return "\n".join(L)

# ------------------------------------------------------------------ issue processing
def has_marker(comments, marker): return any(marker in (c.get("body") or "") for c in comments)

def process(gh, issue, led):
    n = issue["number"]; labels = {l["name"] for l in issue.get("labels", [])}
    author = (issue.get("user") or {}).get("login", "")
    if issue.get("state") != "open" or "paid-scan" not in labels or labels & DONE_LABELS:
        print(f"#{n}: skip (state={issue.get('state')} labels={sorted(labels)})"); return
    f = parse_form(issue.get("body"))
    chain = CHAIN_OPTS.get(f["chain"].lower()); addr = f["address"].split()[0] if f["address"] else ""
    problems = []
    if not chain: problems.append("Chain must be Robinhood Chain (4663) or Base (8453).")
    if not ADDR_RX.match(addr): problems.append("Contract address must be `0x` followed by 40 hexadecimal characters.")
    if problems:
        gh.comment(n, "<!-- lws:needs-info -->\nThanks for the request. I could not start the scan:\n\n" + "\n".join(f"- {p}" for p in problems)
                   + "\n\nEdit the issue to fix it and the check runs again automatically. Your payment (if any) has not been used.")
        gh.add_labels(n, ["needs-info"]); return
    gh.remove_label(n, "needs-info")
    test = ("test" in labels and issue.get("author_association") in ("OWNER", "MEMBER", "COLLABORATOR") and f["txid"].strip().upper() == "TEST")
    pay = entry = None
    if not test:
        pay = check_payment(f["txid"])
        v = pay["verdict"]; print(f"#{n}: payment {v}: {pay['reason']}")
        if v == "invalid":
            extra = (f"\n\n@{MAINTAINER}: payment received but not usable as an instant scan; settle manually (top-up or refund)." if pay.get("underpaid") or pay.get("other_tier") else "")
            gh.comment(n, f"<!-- lws:payment-invalid -->\n**Payment not accepted:** {pay['reason']}\n\nPay {SINGLE_SATS:,} sats (one scan) or {PACK_SATS:,} sats (pack of 5) "
                          f"to `{PAY_ADDR}`, then edit this issue with the new transaction ID. Nothing has been charged or used.{extra}")
            gh.add_labels(n, ["payment-invalid"] + (["needs-maintainer"] if extra else [])); gh.remove_label(n, "awaiting-confirmation"); return
        gh.remove_label(n, "payment-invalid")
        ok, why = ledger_check(led, pay, n, author)
        if not ok:
            gh.comment(n, f"<!-- lws:payment-reused -->\n**Payment not accepted:** {why}\n\nIf you made this payment and believe this is wrong, reply here and the maintainer will sort it out. @{MAINTAINER}")
            gh.add_labels(n, ["payment-invalid", "needs-maintainer"]); gh.remove_label(n, "awaiting-confirmation"); return
        if v == "mixer":
            ledger_record(led, pay, n, author, "refund-due"); led[pay["txid"]]["uses_allowed"] = 0
            save_ledger(led, f"ledger: #{n} mixer-funded payment, refund due")
            gh.comment(n, "<!-- lws:declined-mixer -->\nThanks for your interest. We're sorry, but we can't accept payments sent through mixers or CoinJoin, so we can't run this scan. "
                          "Your payment will be refunded manually: please reply with a BTC refund address.\n\n"
                          f"@{MAINTAINER}: manual refund due ({pay['sats']:,} sats, txid `{pay['txid']}`). Not auto-refunded.")
            gh.add_labels(n, ["declined", "refund-due"]); gh.remove_label(n, "awaiting-confirmation"); return
        if v == "unconfirmed":   # nothing is recorded until the payment confirms
            if not has_marker(gh.comments(n), "lws:waiting"):
                gh.comment(n, f"<!-- lws:waiting -->\nPayment found ({pay['sats']:,} sats), **waiting for confirmation**. "
                              "This issue is re-checked every 15 minutes; the scan runs after 1 confirmation.")
            gh.add_labels(n, ["awaiting-confirmation"]); return
        entry = ledger_record(led, pay, n, author)
        save_ledger(led, f"ledger: claim {pay['txid'][:12]} for #{n}")
        gh.remove_label(n, "awaiting-confirmation")
    if excluded_target(chain, addr):
        return decline_cluster(gh, n, pay, led, entry)
    try:
        r = run_scan(chain, addr, clean_site(f.get("site")))
    except Exception as e:
        print(f"#{n}: scan error {e}")
        tries = sum(1 for c in gh.comments(n) if "lws:scan-error" in (c.get("body") or ""))
        gh.comment(n, f"<!-- lws:scan-error -->\nThe scanner hit an error ({md(str(e), 200)}). Your payment is kept for this issue"
                      + (" and the scan will be retried within 15 minutes." if tries < 2 else f". @{MAINTAINER}: three failed attempts, please check."))
        gh.add_labels(n, ["scan-error"] if tries < 2 else ["needs-maintainer"])
        if tries >= 2: gh.remove_label(n, "scan-error")
        return
    gh.remove_label(n, "scan-error")
    if in_excluded_cluster(r):
        return decline_cluster(gh, n, pay, led, entry)
    uses_left = None
    if entry is not None:
        set_claim(entry, n, "done")
        if entry["uses_allowed"] > 1: uses_left = entry["uses_allowed"] - sum(1 for c in entry["claims"] if c["status"] != "refund-due")
        save_ledger(led, f"ledger: #{n} scanned")
    gh.comment(n, report_md(r, pay, test, uses_left))
    gh.add_labels(n, ["scanned", r["band"].lower()] + (["test"] if test else []))
    gh.close(n, "completed"); print(f"#{n}: scanned {r['score']} {r['band']}, closed")

def decline_cluster(gh, n, pay, led, entry):
    if entry is not None:
        set_claim(entry, n, "refund-due"); save_ledger(led, f"ledger: #{n} excluded target, refund due")
    gh.comment(n, "<!-- lws:declined-excluded -->\nThanks for your request. We're sorry, but this launch is in a group of projects Launch Watch does not offer paid scans for, "
                  "so we won't run it. " + ("Your payment will be refunded manually: please reply with a BTC refund address." if pay else "")
                  + (f"\n\n@{MAINTAINER}: excluded target (hosting cluster); manual refund due ({pay['sats']:,} sats, txid `{pay['txid']}`). Not auto-refunded." if pay else f"\n\n@{MAINTAINER}: excluded target (test issue, no payment)."))
    gh.add_labels(n, ["declined"] + (["refund-due"] if pay else [])); print(f"#{n}: declined (excluded target)")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check-tx"); ap.add_argument("--scan", nargs=2, metavar=("CHAIN", "ADDRESS")); ap.add_argument("--json-in")
    a = ap.parse_args()
    if a.check_tx:
        print(json.dumps(check_payment(a.check_tx), indent=1)); return
    if a.scan:
        r = json.load(open(a.json_in)) if a.json_in else run_scan(*a.scan)
        print("excluded cluster:", in_excluded_cluster(r) or excluded_target(*a.scan), file=sys.stderr)
        print(report_md(r, None, test=True)); return
    gh = GH(); led = load_ledger()
    ev = os.environ.get("GITHUB_EVENT_NAME", "")
    if ev == "issues":
        n = json.load(open(os.environ["GITHUB_EVENT_PATH"]))["issue"]["number"]
        issues = [gh.issue(n)]   # re-read: labels may have changed since the event
    else:
        issues = list(gh.open_requests())
    failed = 0
    for it in issues:
        try: process(gh, it, led)
        except Exception as e:
            failed += 1; print(f"#{it['number']}: ERROR {e}", file=sys.stderr)
    print(f"processed {len(issues)} issue(s), {failed} error(s)")
    sys.exit(1 if failed else 0)

if __name__ == "__main__":
    main()
