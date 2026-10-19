#!/usr/bin/env python3
"""Metatron Launch Watch - score.py (v0)

Deterministic, explainable 0-100 RISK score for a newly launched token or contract
on Robinhood Chain (4663) or Base (8453). Higher = more risk signals.

Usage:
  python3 score.py --chain robinhood --address 0x... [--site https://...] [--post URL]
                   [--x-created 2026-10-14T08:30:00Z] [--json] [--out file.md] [--raw-dir DIR]

Rules this file follows:
  * Only public, free, keyless data: chain RPC, Sourcify, Blockscout, GoPlus, honeypot.is (Base),
    DexScreener, GeckoTerminal, Google DNS-over-HTTPS, RDAP. Blockscout calls retry with backoff
    on Cloudflare 403 / 429 / 5xx (the Blockscout PRO API is used if BLOCKSCOUT_API_KEY is set).
  * v0.2.0 accuracy fixes (2026-10-15):
      - source verified on Sourcify OR Blockscout = verified (an EIP-1167 clone counts when its implementation is
        verified, as Blockscout shows it); 'unverified' only when both answered; if a lookup failed and the other
        has no match -> 'unknown'.
      - LP held by a verified locker contract (or burned) is not scored as unlocked, whatever GoPlus says.
      - EIP-7702 delegated wallets (code 0xef0100 + delegate) are single keys, not multisig/timelock.
      - privileged functions are informational when owner() is absent/renounced, AccessControl shows no
        live role holder (RoleGranted/RoleRevoked logs + hasRole on the deployer) and no initializer is open.
  * Every check returns status flag | pass | info | unknown, fixed points from WEIGHTS,
    and evidence (links / exact RPC calls). Nothing is inferred without a data point.
  * A check that cannot run is 'unknown' and adds a small, fixed uncertainty weight
    (UNKNOWN_POINTS) so missing data never looks "safe". It is never guessed.
  * Wording: findings are 'risk signals', never claims about intent.
Reuses: GoPlus + honeypot.is query pattern from github.com/invisiblemonsters/token-launch-scan
(MIT).
"""
import argparse, datetime as dt, json, os, re, sys, time, urllib.parse, urllib.request
from Crypto.Hash import keccak

HERE = os.path.dirname(os.path.abspath(__file__))
UA = {"User-Agent": "Mozilla/5.0 (MetatronLaunchWatch/0.1; research)", "Accept": "application/json"}
VERSION = "0.2.0"

CHAINS = {
    "robinhood": {
        "id": 4663, "name": "Robinhood Chain",
        "rpcs": ["https://rpc.mainnet.chain.robinhood.com"],
        "archive_rpcs": [],  # public RPC keeps only recent state (tested 2026-10-14)
        "logs_rpc": "https://rpc.mainnet.chain.robinhood.com", "logs_span": 9_000_000,
        "explorer": "https://robinhoodchain.blockscout.com",
        "blockscout_api": "https://robinhoodchain.blockscout.com/api/v2",
        "role_logs_rpcs": ["https://rpc.mainnet.chain.robinhood.com"],
        "dexscreener": "robinhood", "gecko": "robinhood", "goplus": "4663", "honeypot": None,
    },
    "base": {
        "id": 8453, "name": "Base",
        "rpcs": ["https://mainnet.base.org", "https://base.drpc.org", "https://base-rpc.publicnode.com"],
        "archive_rpcs": ["https://mainnet.base.org", "https://base.drpc.org"],
        "logs_rpc": "https://base.drpc.org", "logs_span": 9_900,
        "explorer": "https://base.blockscout.com",
        "blockscout_api": "https://base.blockscout.com/api/v2",
        "role_logs_rpcs": ["https://base-rpc.publicnode.com", "https://base.drpc.org"],
        "dexscreener": "base", "gecko": "base", "goplus": "8453", "honeypot": "8453",
    },
}

UNKNOWN_POINTS = 3
WEIGHTS = {  # points added when the check FLAGS. Documented in PLAN.md / report.
    "not_contract": 40,
    "unverified": 15, "unverified_template_match": 4,
    "upgradeable_proxy": 15,
    "proxy_admin_eoa": 5,
    "owner_eoa": 8,
    "owner_contract": 3,
    "fn_mint": 12, "fn_blacklist": 12, "fn_pause": 8, "fn_fee_setter": 8,
    "fn_withdraw": 5, "fn_upgrade": 10, "fn_trading_switch": 6,
    "honeypot": 35, "high_tax": 10, "goplus_flag": 8, "same_creator_honeypot": 15,
    "low_liquidity": 10, "very_low_liquidity": 15, "no_pool": 6, "lp_unlocked": 12,
    "launcher_holds_supply": 10, "holder_concentration": 10,
    "fresh_deployer": 8, "serial_deployer": 8, "young_deployer": 6,
    "hosting_cluster": 25, "hosting_cluster_subnet": 8, "young_domain": 5, "young_x_account": 4,
}
OWNER_RENOUNCED_FACTOR = 0.5  # privileged-function points halved when owner() is provably 0x0/dead

ZERO = "0x" + "0" * 40
ENTRYPOINTS = {"0x5ff137d4b0fdcd49dca30c7cf57e578a026d2789", "0x0000000071727de22e5e9d8baf0edac6f37da032", "0x4337084d9e255ff0702461cf8895ce9e3b5ff108"}
PLATFORM_SUFFIXES = (".lovable.app", ".vercel.app", ".netlify.app", ".github.io", ".pages.dev", ".webflow.io", ".framer.website",
                     ".framer.ai", ".carrd.co", ".replit.app", ".onrender.com", ".gitbook.io", ".wixsite.com", ".myshopify.com")
CLONE_RX = [  # minimal proxies (clones): no logic of their own, delegate every call to a fixed implementation
    re.compile(r"0x363d3d373d3d3d363d73([0-9a-f]{40})5af43d82803e903d91602b57fd5bf3"),  # EIP-1167
    re.compile(r"0x3d3d3d3d363d3d37363d73([0-9a-f]{40})5af43d3d93803e602a57fd5bf3"),    # 0age 44-byte variant (Blockscout: eip1167)
    re.compile(r"0x365f5f375f5f365f73([0-9a-f]{40})5af43d5f5f3e5f3d91602a57fd5bf3"),    # ERC-7511 PUSH0 clone
]
def clone_impl(code):
    for rx in CLONE_RX:
        m = rx.fullmatch((code or "").lower())
        if m: return "0x" + m.group(1)
    return None
def is_7702(code): return bool(code) and code.lower().startswith("0xef0100")
DEAD = {"0x000000000000000000000000000000000000dead", "0xdead000000000000000042069420694206942069", ZERO}
TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
SLOT_IMPL = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
SLOT_ADMIN = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
SLOT_BEACON = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"

def k256(b):
    h = keccak.new(digest_bits=256); h.update(b); return h.hexdigest()

def sel(sig):
    return "0x" + k256(sig.encode())[:8]

PRIV_SIGS = {
    "fn_mint": ["mint(address,uint256)", "mint(uint256)", "mintTo(address,uint256)", "mint(address)", "ownerMint(address,uint256)"],
    "fn_pause": ["pause()", "unpause()", "setPaused(bool)", "pauseTransfers()", "setPause(bool)"],
    "fn_blacklist": ["blacklist(address)", "addToBlacklist(address)", "setBlacklist(address,bool)", "blacklistAddress(address,bool)",
                     "addBlacklist(address)", "setBot(address,bool)", "setBots(address[],bool)", "addBots(address[])",
                     "blockBots(address[])", "setIsBlacklisted(address,bool)", "updateBlacklist(address,bool)",
                     "setBlocklist(address,bool)", "addToBlocklist(address)", "ban(address)", "setBlackList(address,bool)"],
    "fn_fee_setter": ["setFee(uint256)", "setFees(uint256,uint256)", "setTaxes(uint256,uint256)", "setBuyFee(uint256)",
                      "setSellFee(uint256)", "setBuyTax(uint256)", "setSellTax(uint256)", "updateFees(uint256,uint256)",
                      "setTaxFeePercent(uint256)", "setFeePercent(uint256)", "setSwapFee(uint256)",
                      "updateBuyFees(uint256,uint256,uint256)", "updateSellFees(uint256,uint256,uint256)",
                      "setTax(uint256)", "setFees(uint256,uint256,uint256)", "setMaxTxAmount(uint256)",
                      "setMaxWalletSize(uint256)", "setMaxWallet(uint256)", "setTaxWallet(address)"],
    "fn_trading_switch": ["enableTrading()", "openTrading()", "setTradingEnabled(bool)", "setTrading(bool)", "startTrading()"],
    "fn_withdraw": ["withdraw()", "withdraw(uint256)", "emergencyWithdraw()", "rescueTokens(address,uint256)", "rescueETH()",
                    "sweep(address)", "withdrawTokens(address)", "recoverERC20(address,uint256)", "clearStuckBalance()",
                    "withdrawETH()", "rescueERC20(address,uint256)", "emergencyWithdraw(address)", "withdrawAll()"],
    "fn_upgrade": ["upgradeTo(address)", "upgradeToAndCall(address,bytes)"],
}
SEL_TO_SIG = {sel(s): (cat, s) for cat, sigs in PRIV_SIGS.items() for s in sigs}
NAME_RX = {  # ABI name patterns (only used when the ABI is available from a verified source)
    "fn_mint": r"^(mint|_?ownerMint|mintTo)$",
    "fn_pause": r"^(pause|unpause|setPaused|setPause)$",
    "fn_blacklist": r"(black|block)list|^setBots?$|^addBots$|^ban$|blockBots",
    "fn_fee_setter": r"^(set|update)\w*(Fee|Fees|Tax|Taxes|MaxTx\w*|MaxWallet\w*)$",
    "fn_trading_switch": r"^(enableTrading|openTrading|setTradingEnabled|setTrading|startTrading)$",
    "fn_withdraw": r"^(withdraw\w*|emergencyWithdraw\w*|rescue\w*|sweep\w*|recover\w*|clearStuck\w*)$",
    "fn_upgrade": r"^upgradeTo(AndCall)?$",
}
FN_LABEL = {"fn_mint": "mint", "fn_pause": "pause", "fn_blacklist": "blacklist/bot-block", "fn_fee_setter": "fee/tax/limit setter",
            "fn_trading_switch": "trading on/off switch", "fn_withdraw": "withdraw/rescue", "fn_upgrade": "upgrade"}

# ---------------------------------------------------------------- HTTP / RPC
class Net:
    def __init__(self, chain):
        self.c = CHAINS[chain]; self.log = []; self.rpc_i = 0; self.pin_fallbacks = 0; self.archive_call = False

    def get(self, url, timeout=25, raw=False, headers=None, retries=None):
        """GET with JSON decode. Blockscout sits behind Cloudflare and intermittently answers 403 (challenge),
        429 or 5xx, so Blockscout URLs are retried with exponential backoff (BLOCKSCOUT_RETRIES, default 3)."""
        h = dict(UA); h.update(headers or {})
        if retries is None:
            retries = int(os.environ.get("BLOCKSCOUT_RETRIES", "3")) if "blockscout.com" in url else 0
        for attempt in range(retries + 1):
            req = urllib.request.Request(url, headers=h)
            err = None
            try:
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    body = r.read().decode("utf-8", "replace"); code = r.status
            except urllib.error.HTTPError as e:
                body = e.read().decode("utf-8", "replace")[:300]; code = e.code
            except Exception as e:
                err = str(e)[:160]; code = None; body = ""
            if err is not None:
                self.log.append({"url": url, "err": err, "attempt": attempt + 1})
            else:
                self.log.append({"url": url, "status": code, **({"attempt": attempt + 1} if attempt else {})})
            retryable = err is not None or code in (403, 408, 425, 429, 500, 502, 503, 504, 520, 521, 522, 523, 524)
            if not retryable or attempt == retries: break
            time.sleep(min(20, 2.0 * 2 ** attempt))  # 2s, 4s, 8s
        if err is not None:
            return None, f"ERR {err[:120]}" + (f" after {attempt + 1} tries" if attempt else "")
        if code != 200:
            return None, f"HTTP {code}" + (" (Cloudflare challenge)" if "Just a moment" in body else "") + (f" after {attempt + 1} tries" if attempt else "")
        if raw: return body, None
        try: return json.loads(body), None
        except Exception: return None, "non-JSON response"

    def rpc(self, method, params, urls=None, tries=3):
        urls = urls or self.c["rpcs"]; last = None
        for attempt in range(tries):
            for u in urls:
                body = json.dumps({"id": 1, "jsonrpc": "2.0", "method": method, "params": params}).encode()
                req = urllib.request.Request(u, data=body, headers={"content-type": "application/json", **UA})
                try:
                    with urllib.request.urlopen(req, timeout=30) as r:
                        d = json.loads(r.read())
                except Exception as e:
                    last = str(e)[:120]; continue
                if "error" in d:
                    last = str(d["error"].get("message"))[:160]
                    if ("unsupported block number" in last or "header not found" in last) and attempt == 0:
                        time.sleep(1.0); break
                    if ("historical state" in last or "unsupported block number" in last or "header not found" in last) and params and isinstance(params[-1], str) and params[-1].startswith("0x") and method != "eth_getBlockByNumber" and not self.archive_call:
                        params = list(params[:-1]) + ["latest"]; self.pin_fallbacks += 1; continue
                    if "limit" in last.lower() or "many" in last.lower():
                        continue
                    return None, last
                return d.get("result"), None
            time.sleep(1.5 * (attempt + 1))
        return None, last

    def batch_code(self, addrs, block):
        out = {}
        for i in range(0, len(addrs), 50):
            chunk = addrs[i:i + 50]
            body = json.dumps([{"id": j, "jsonrpc": "2.0", "method": "eth_getCode", "params": [a, block]} for j, a in enumerate(chunk)]).encode()
            req = urllib.request.Request(self.c["rpcs"][0], data=body, headers={"content-type": "application/json", **UA})
            try:
                with urllib.request.urlopen(req, timeout=40) as r:
                    res = json.loads(r.read())
                for x in res:
                    out[chunk[x["id"]]] = x.get("result")
            except Exception:
                for a in chunk:
                    out[a], _ = self.rpc("eth_getCode", [a, block])
        return out

def call(net, to, data, block):
    return net.rpc("eth_call", [{"to": to, "data": data}, block])

def word_addr(w):
    if not w or len(w) < 66: return None
    return "0x" + w[-40:].lower()

def dec_str(h):
    try:
        b = bytes.fromhex(h[2:])
        if len(b) >= 64:
            ln = int.from_bytes(b[32:64], "big"); return b[64:64 + ln].decode("utf-8", "replace")
        return b.rstrip(b"\0").decode("utf-8", "replace")
    except Exception: return None

def create_addr(sender, nonce):
    def rlp_bytes(b):
        if len(b) == 1 and b[0] < 0x80: return b
        return bytes([0x80 + len(b)]) + b
    s = bytes.fromhex(sender[2:])
    n = b"" if nonce == 0 else nonce.to_bytes((nonce.bit_length() + 7) // 8, "big")
    payload = rlp_bytes(s) + rlp_bytes(n)
    return "0x" + k256(bytes([0xc0 + len(payload)]) + payload)[-40:]

def push4_selectors(code_hex):
    code = bytes.fromhex(code_hex[2:]) if code_hex and code_hex.startswith("0x") else b""
    out, i = set(), 0
    while i < len(code):
        op = code[i]
        if 0x60 <= op <= 0x7f:
            n = op - 0x5f
            if op == 0x63 and i + 5 <= len(code): out.add("0x" + code[i + 1:i + 5].hex())
            i += n + 1
        else: i += 1
    return out

# ---------------------------------------------------------------- check helper
class Report:
    def __init__(self): self.checks = []
    def add(self, cid, title, status, detail, evidence=None, weight_key=None, points=None, group=None):
        if points is None:
            points = WEIGHTS.get(weight_key, 0) if status == "flag" else (UNKNOWN_POINTS if status == "unknown" else 0)
        self.checks.append({"id": cid, "group": group or cid.split(".")[0], "title": title, "status": status,
                            "points": round(points, 1), "detail": detail, "evidence": [e for e in (evidence or []) if e]})

_TPL = {}
def template_match(net, chain, code, block):
    key = (chain, len(code))
    if key in _TPL: return _TPL[key]
    _TPL[key] = None
    try: T = json.load(open(os.path.join(HERE, "data", "templates.json")))["templates"]
    except Exception: return None
    mine = bytes.fromhex(code[2:])
    for t in T:
        if t["chain"] != chain: continue
        ref, _ = net.rpc("eth_getCode", [t["address"], block])
        if not ref or len(ref) != len(code): continue
        rb = bytes.fromhex(ref[2:]); same = sum(1 for x, y in zip(mine, rb) if x == y) * 100 / len(rb)
        if same >= 97:
            _TPL[key] = dict(t, same_pct=same); break
    return _TPL[key]

# ---------------------------------------------------------------- verification (Sourcify OR Blockscout)
def verify_lookup(net, address, sfy_fields="abi,deployment,proxyResolution,compilation"):
    """Look a contract up on Sourcify and on Blockscout. Verified on EITHER counts as verified.
    state: 'verified' | 'not_verified' (both sources answered, neither has it) | 'unknown' (a source could not be checked
    and the other did not confirm verification). Results are cached per scan."""
    cache = net.__dict__.setdefault("_verify_cache", {})
    k = address.lower()
    if k in cache: return cache[k]
    c = net.c
    sfy, err_s = net.get(f"https://sourcify.dev/server/v2/contract/{c['id']}/{address}?fields={sfy_fields}")
    sfy_match = (sfy or {}).get("match")
    sfy_state = "verified" if sfy_match in ("exact_match", "match") else ("not_verified" if (sfy is not None or (err_s or "").startswith("HTTP 404")) else "error")
    key = os.environ.get("BLOCKSCOUT_API_KEY")
    if key:
        bsj, bs_err = net.get(f"https://api.blockscout.com/{c['id']}/api/v2/smart-contracts/{address}?apikey={key}")
    else:
        bsj, bs_err = net.get(f"{c['blockscout_api']}/smart-contracts/{address}")
    if isinstance(bsj, dict):
        bs_ver = bool(bsj.get("is_verified") or bsj.get("source_code"))
        bs_status = "verified" if bs_ver else "not verified"
        bs_state = "verified" if bs_ver else "not_verified"
    else:  # incl. HTTP 404: Blockscout has no contract record yet (not indexed), so nothing can be concluded
        bs_status, bs_state = None, "error"
    if "verified" in (sfy_state, bs_state): state = "verified"
    elif sfy_state == "not_verified" and bs_state == "not_verified": state = "not_verified"
    else: state = "unknown"
    out = {"state": state, "sfy": sfy, "sfy_match": sfy_match, "sfy_err": err_s, "sfy_state": sfy_state,
           "bs": bsj if isinstance(bsj, dict) else None, "bs_status": bs_status, "bs_err": bs_err, "bs_state": bs_state,
           "bs_partial": bool(isinstance(bsj, dict) and bsj.get("is_partially_verified")),
           "abi": (sfy or {}).get("abi") or (bsj.get("abi") if isinstance(bsj, dict) else None),
           "name": (((sfy or {}).get("compilation") or {}).get("name") if sfy else None) or (bsj.get("name") if isinstance(bsj, dict) else None),
           "verified_on": [n for n, st in (("Sourcify", sfy_state), ("Blockscout", bs_state)) if st == "verified"]}
    cache[k] = out
    return out

LOCKER_NAME_RX = re.compile(r"lock", re.I)
LOCKER_FN_RX = re.compile(r"^lock", re.I)

def locker_info(net, address, block):
    """A 'verified locker' = a real contract (not an EIP-7702 delegated wallet) whose source is verified on Sourcify or
    Blockscout and whose contract name contains 'Lock' or which exposes a lock*() function. Lock terms are NOT analysed."""
    cache = net.__dict__.setdefault("_locker_cache", {})
    k = address.lower()
    if k in cache: return cache[k]
    cache[k] = None
    code, _ = net.rpc("eth_getCode", [k, block])
    if not code or code in ("0x", "0x0") or is_7702(code): return None
    v = verify_lookup(net, k, sfy_fields="abi,compilation")
    if v["state"] != "verified": return None
    name = v.get("name") or ""
    fns = [f.get("name") or "" for f in (v.get("abi") or []) if isinstance(f, dict) and f.get("type") == "function"]
    if LOCKER_NAME_RX.search(name) or any(LOCKER_FN_RX.match(n) for n in fns):
        cache[k] = {"address": k, "name": name or "unnamed", "verified_on": v["verified_on"]}
    return cache[k]

# ---------------------------------------------------------------- role holders (OpenZeppelin AccessControl)
ROLE_GRANTED = "0x" + k256(b"RoleGranted(bytes32,address,address)")
ROLE_REVOKED = "0x" + k256(b"RoleRevoked(bytes32,address,address)")
INITIALIZED_TOPICS = ["0x" + k256(b"Initialized(uint64)"), "0x" + k256(b"Initialized(uint8)")]
OZ5_INITIALIZABLE_SLOT = "0xf0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a00"
SEL_HASROLE = sel("hasRole(bytes32,address)")
INIT_NAME_RX = re.compile(r"^_*(initiali[sz]e|init)\w*$", re.I)

def bs_logs(net, address, topic0):
    """All logs of `address` with topic0, via Blockscout's Etherscan-compatible API (full history, one call)."""
    u = f"{net.c['explorer']}/api?module=logs&action=getLogs&address={address}&topic0={topic0}&fromBlock=0&toBlock=latest"
    d, e = net.get(u)
    if d is None: return None, e, u
    res = d.get("result")
    if str(d.get("status")) == "1" and isinstance(res, list):
        if len(res) >= 1000: return None, "result truncated at 1000 logs", u
        return res, None, u
    if str(d.get("status")) == "0" and "no logs found" in str(d.get("message", "")).lower(): return [], None, u
    return None, f"unexpected answer: {str(d.get('message'))[:80]}", u

def rpc_logs(net, address, topic0, frm, to):
    """Chunked eth_getLogs fallback from the creation block (complete only if every chunk answers)."""
    span = net.c["logs_span"]; out = []; n = 0
    while frm <= to:
        n += 1
        if n > 150: return None, "too many log chunks"
        hi = min(to, frm + span - 1)
        logs, e = net.rpc("eth_getLogs", [{"fromBlock": hex(frm), "toBlock": hex(hi), "address": address, "topics": [topic0]}],
                          urls=net.c.get("role_logs_rpcs") or [net.c["logs_rpc"]], tries=2)
        if logs is None: return None, e
        out += logs; frm = hi + 1
    return out, None

def role_holders(net, a, creation_block, bn):
    """Net (role, account) holders from RoleGranted/RoleRevoked logs. Returns (set, source, err)."""
    got = {}
    src = None
    for nm, t in (("granted", ROLE_GRANTED), ("revoked", ROLE_REVOKED)):
        logs, e, u = bs_logs(net, a, t)
        if logs is not None: src = src or u
        if logs is None and creation_block and bn:
            logs, e = rpc_logs(net, a, t, creation_block, bn); src = src or f"eth_getLogs {a} topic0={t[:10]}.. blocks {creation_block}-{bn}"
        if logs is None: return None, None, e
        got[nm] = logs
    ev = []
    for nm, logs in got.items():
        for l in logs:
            tp = l.get("topics") or []
            if len(tp) < 3 or not tp[1] or not tp[2]: continue
            ev.append((int(str(l.get("blockNumber") or "0x0"), 16), int(str(l.get("logIndex") or "0x0"), 16), nm, tp[1].lower(), word_addr(tp[2])))
    holders = set()
    for _, _, nm, role, acct in sorted(ev):
        (holders.add if nm == "granted" else holders.discard)((role, acct))
    return holders, src, None

def role_check(net, a, block, bn, abis, codes, creation, owner):
    """Can anyone call the privileged functions? Returns (downgrade: bool, note, evidence)."""
    cands = [x for x in dict.fromkeys([creation.get("deployer"), creation.get("tx_from"), creation.get("factory_or_deployer"), owner]) if x and x not in DEAD]
    probe = cands[0] if cands else ZERO
    r, _ = call(net, a, SEL_HASROLE + "0" * 64 + "0" * 24 + probe[2:], block)
    if not r or len(r) < 66 or int(r, 16) > 1:
        return False, "No OpenZeppelin AccessControl hasRole() answered, so role holders could not be checked.", []
    ev = [f"eth_call {a} hasRole(DEFAULT_ADMIN_ROLE, {probe}) @ {bn} = {bool(int(r, 16))}"]
    for x in cands:
        r2, _ = call(net, a, SEL_HASROLE + "0" * 64 + "0" * 24 + x[2:], block) if x != probe else (r, None)
        if r2 and len(r2) >= 66 and int(r2, 16) == 1:
            return False, f"hasRole(DEFAULT_ADMIN_ROLE, {x}) = true: an admin role holder exists.", ev
    holders, src, err = role_holders(net, a, creation.get("block"), bn)
    if holders is None:
        return False, f"AccessControl present, but RoleGranted logs could not be read ({err}); role holders unconfirmed.", ev
    ev.append(src)
    if holders:
        return False, f"{len(holders)} role assignment(s) are live according to RoleGranted/RoleRevoked logs (e.g. {sorted(holders)[0][1]}).", ev
    # no role holders: make sure an initializer can't still hand out roles
    has_init = any(INIT_NAME_RX.match(f.get("name") or "") for ab in abis if ab for f in ab if isinstance(f, dict) and f.get("type") == "function")
    has_init = has_init or any(cd and ("7f" + t[2:]) in cd.lower() for cd in codes for t in INITIALIZED_TOPICS)
    init_note = ""
    if has_init:
        v, _ = net.rpc("eth_getStorageAt", [a, OZ5_INITIALIZABLE_SLOT, block])
        consumed = bool(v and int(v, 16))
        if consumed:
            init_note = f" Initializer already consumed or disabled (OpenZeppelin v5 Initializable slot = {int(v, 16) & (2**64 - 1)})."
            ev.append(f"eth_getStorageAt({a}, Initializable slot) @ {bn}")
        else:
            ilogs = []
            for t in INITIALIZED_TOPICS:
                lg, e, u = bs_logs(net, a, t)
                if lg is None: return False, f"No role holders, but the contract has an initializer and its state could not be confirmed ({e}).", ev
                ilogs += lg
                if lg: ev.append(u)
            if not ilogs:
                return False, "No role holders yet, but the contract has an initializer that has not been run or disabled, so roles can still be granted.", ev
            init_note = f" Initializer already run or disabled ({len(ilogs)} Initialized event(s))."
    note = (" Downgraded to informational: the contract uses OpenZeppelin AccessControl and no account holds any role "
            "(no live RoleGranted assignment since deployment; DEFAULT_ADMIN_ROLE not held by the deployer/launcher), "
            "so role-gated functions cannot currently be called." + init_note +
            " Functions gated by something other than roles are not ruled out.")
    return True, note, ev

# ---------------------------------------------------------------- main scorer
def score(chain, address, site=None, post=None, x_created=None, now=None):
    net = Net(chain); c = net.c; R = Report()
    a = address.lower(); now = now or dt.datetime.now(dt.timezone.utc)
    exp_addr = f"{c['explorer']}/address/{address}"
    bn_hex, err = net.rpc("eth_blockNumber", [])
    block = bn_hex or "latest"; bn = int(bn_hex, 16) if bn_hex else None
    res = {"tool": "Metatron Launch Watch", "version": VERSION, "chain": chain, "chain_id": c["id"], "address": address,
           "scanned_at_utc": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "block": bn, "site": site, "post": post}
    def blk_ts(b):
        r, _ = net.rpc("eth_getBlockByNumber", [b, False]); return int(r["timestamp"], 16) if r else None

    # 1. code -----------------------------------------------------------------
    code, err = net.rpc("eth_getCode", [a, block])
    if code is None:
        R.add("code.exists", "Contract code present", "unknown", f"eth_getCode failed: {err}")
        return finalize(res, R)
    elif code in ("0x", "0x0"):
        R.add("code.exists", "Contract code present", "flag", "No bytecode at this address (EOA or not deployed on this chain).",
              [f"eth_getCode({a}, {block}) = 0x", exp_addr], "not_contract")
        res["checks"] = R.checks; return finalize(res, R)
    else:
        R.add("code.exists", "Contract code present", "info", f"{(len(code) - 2) // 2} bytes of runtime code.", [f"eth_getCode @ block {bn}", exp_addr])

    # token basics
    tok = {}
    for k, s in (("name", "0x06fdde03"), ("symbol", "0x95d89b41"), ("decimals", "0x313ce567"), ("totalSupply", "0x18160ddd")):
        r, _ = call(net, a, s, block)
        if r and r != "0x":
            tok[k] = dec_str(r) if k in ("name", "symbol") else int(r, 16)
    res["token"] = tok
    is_token = "totalSupply" in tok

    # 2. verification -----------------------------------------------------------
    # Verified on Sourcify OR Blockscout counts. 'unverified' only when BOTH answered and neither has source;
    # if a source could not be checked (e.g. Cloudflare 403 after retries) and the other has no match -> 'unknown'.
    abi, impl_abi = None, None
    V = dict(verify_lookup(net, address))
    clone_m = clone_impl(code)
    if V["state"] != "verified" and clone_m:
        # An EIP-1167 clone has no logic of its own: it delegates every call to its implementation. Blockscout shows
        # such clones as verified when the implementation is (addresses API is_verified=true), so count them too.
        cimpl = clone_m
        IV = verify_lookup(net, cimpl, sfy_fields="abi,compilation")
        V["clone_of"] = {"address": cimpl, "state": IV["state"], "name": IV.get("name"), "verified_on": IV["verified_on"]}
        if IV["state"] == "verified":
            V.update(state="verified", verified_on=[f"{x} (via implementation)" for x in IV["verified_on"]], name=IV.get("name"))
    sfy, sfy_match, err_s, bs_status, bs_err = V["sfy"], V["sfy_match"], V["sfy_err"], V["bs_status"], V["bs_err"]
    sfy_link = f"https://repo.sourcify.dev/{c['id']}/{address}"
    bs_tab = f"{c['explorer']}/address/{address}?tab=contract"
    abi = V["abi"]
    res["sourcify"] = {"match": sfy_match, "err": err_s}
    res["blockscout"] = {"status": bs_status, "err": bs_err, **({"partial": True} if V["bs_partial"] else {}),
                         **({"name": V["bs"].get("name")} if V["bs"] and V["bs"].get("name") else {})}
    res["verification"] = V["state"]
    if V.get("clone_of"): res["verification_clone_of"] = V["clone_of"]
    sfy_txt = sfy_match or ("no match" if V["sfy_state"] == "not_verified" else f"not checked ({err_s})")
    bs_txt = (bs_status + (" (partial match)" if V["bs_partial"] else "")) if bs_status else f"not checked ({bs_err})"
    if V["state"] == "verified" and V.get("clone_of"):
        ci = V["clone_of"]
        R.add("verify.source", "Source verified", "pass",
              f"EIP-1167 clone with no logic of its own; every call runs implementation {ci['name'] or ''} {ci['address']}, which is verified on {' and '.join(ci['verified_on'])}. "
              f"The clone itself: Sourcify {sfy_txt}; Blockscout {bs_txt} (Blockscout lists the clone as verified via its implementation).",
              [f"{c['explorer']}/address/{ci['address']}?tab=contract", bs_tab, f"{c['blockscout_api']}/addresses/{address}"])
    elif V["state"] == "verified":
        R.add("verify.source", "Source verified", "pass",
              f"Verified on {' and '.join(V['verified_on'])}" + (f" as {V['name']}" if V.get("name") else "") + f". Sourcify: {sfy_txt}; Blockscout: {bs_txt}.",
              [sfy_link if V["sfy_state"] == "verified" else None, bs_tab])
    elif V["state"] == "unknown":
        tm = template_match(net, chain, code, block)
        R.add("verify.source", "Source verified", "unknown",
              f"Verification could not be confirmed either way. Sourcify: {sfy_txt}; Blockscout: {bs_txt}. Not scored as unverified."
              + (f" Runtime bytecode matches verified template {tm['name']} ({tm['address']})." if tm else ""),
              [f"https://sourcify.dev/server/v2/contract/{c['id']}/{address}", bs_tab, f"{c['blockscout_api']}/smart-contracts/{address}"])
    elif template_match(net, chain, code, block):
        tm = template_match(net, chain, code, block)
        R.add("verify.source", "Source verified", "flag",
              f"Not verified itself (Sourcify: no match; Blockscout: not verified), but runtime bytecode matches verified template {tm['name']} ({tm['address']}): same length, {tm['same_pct']:.1f}% identical bytes (differences are constructor immutables).",
              [tm["evidence"], bs_tab], "unverified_template_match")
    else:
        R.add("verify.source", "Source verified", "flag",
              "Not verified on Sourcify (no match) and not verified on Blockscout (both lookups answered).",
              [f"https://sourcify.dev/server/v2/contract/{c['id']}/{address}", bs_tab, f"{c['blockscout_api']}/smart-contracts/{address}"], "unverified")

    # deployment (Sourcify) -> creation tx / deployer
    deploy = (sfy or {}).get("deployment") or {}
    creation = {"tx": deploy.get("transactionHash"), "block": int(deploy["blockNumber"]) if deploy.get("blockNumber") else None,
                "deployer": (deploy.get("deployer") or "").lower() or None, "source": "Sourcify deployment" if deploy else None}

    bsa, bsa_err = net.get(f"{c['blockscout_api']}/addresses/{address}")
    if bsa and bsa.get("creation_transaction_hash") and not creation["tx"]:
        creation.update(tx=bsa["creation_transaction_hash"], deployer=(bsa.get("creator_address_hash") or "").lower() or None,
                        source="Blockscout address creator")
    elif bsa and bsa.get("creator_address_hash"):
        creation["factory_or_deployer"] = bsa["creator_address_hash"].lower()

    # 3. proxy ----------------------------------------------------------------------
    impl = None
    m = clone_impl(code)
    slots = {}
    for nm, s in (("impl", SLOT_IMPL), ("admin", SLOT_ADMIN), ("beacon", SLOT_BEACON)):
        v, e = net.rpc("eth_getStorageAt", [a, s, block])
        slots[nm] = word_addr(v) if v and int(v, 16) else None
    pr = (sfy or {}).get("proxyResolution") or {}
    if m:
        impl = m
        R.add("proxy.type", "Proxy / upgradeability", "info", f"EIP-1167-style minimal proxy (clone) of {impl}; clones are NOT upgradeable.",
              [f"bytecode is a minimal-proxy pattern ({(len(code) - 2) // 2} bytes) delegating to {impl}", f"{c['explorer']}/address/{impl}"])
    elif slots["impl"] or slots["beacon"]:
        impl = slots["impl"]
        admin = slots["admin"]
        R.add("proxy.type", "Proxy / upgradeability", "flag",
              f"EIP-1967 proxy: implementation {slots['impl']}, beacon {slots['beacon']}, admin slot {admin}. Logic can be swapped by whoever controls upgrades.",
              [f"eth_getStorageAt({a}, {SLOT_IMPL[:10]}..) @ {bn}", f"{c['explorer']}/address/{impl or slots['beacon']}"], "upgradeable_proxy")
        if admin:
            acode, _ = net.rpc("eth_getCode", [admin, block])
            if acode == "0x":
                R.add("proxy.admin", "Proxy admin is a plain wallet", "flag", f"Proxy admin {admin} has no code (single key).",
                      [f"eth_getCode({admin}) = 0x", f"{c['explorer']}/address/{admin}"], "proxy_admin_eoa")
            elif is_7702(acode):
                R.add("proxy.admin", "Proxy admin is a plain wallet", "flag",
                      f"Proxy admin {admin} is a wallet with an EIP-7702 delegation to {'0x' + acode[8:48]} (code prefix 0xef0100); it is still controlled by a single private key.",
                      [f"eth_getCode({admin}) = {acode[:10]}…", f"{c['explorer']}/address/{admin}"], "proxy_admin_eoa")
    elif pr.get("isProxy"):
        R.add("proxy.type", "Proxy / upgradeability", "flag", f"Sourcify proxyResolution: {pr.get('proxyType')} -> {pr.get('implementations')}",
              [sfy_link], "upgradeable_proxy")
        impl = ((pr.get("implementations") or [{}])[0] or {}).get("address")
    else:
        R.add("proxy.type", "Proxy / upgradeability", "pass", "No EIP-1967 impl/beacon slot set, not an EIP-1167 clone" +
              (", Sourcify proxyResolution isProxy=false." if pr else "."), [f"eth_getStorageAt slots 1967 impl/admin/beacon @ {bn}"])
    impl_code = None
    if impl:
        impl_code, _ = net.rpc("eth_getCode", [impl, block])
        iv = verify_lookup(net, impl, sfy_fields="abi,compilation")
        if iv.get("abi"): impl_abi = iv["abi"]

    # 4. owner / admin -----------------------------------------------------------------
    owner, owner_src = None, None
    for s, nm in (("0x8da5cb5b", "owner()"), ("0x893d20e8", "getOwner()")):
        r, _ = call(net, a, s, block)
        if r and len(r) >= 66:
            owner, owner_src = word_addr(r), nm; break
    renounced = False
    if owner is None:
        R.add("owner.owner", "Owner / admin", "info", "No owner()/getOwner() function answered (no Ownable-style owner). Role-based admin may still exist.",
              [f"eth_call {a} owner() @ {bn} -> revert/empty"])
    elif owner in DEAD:
        renounced = True
        R.add("owner.owner", "Owner / admin", "pass", f"{owner_src} = {owner} (renounced).", [f"eth_call {a} {owner_src} @ {bn}"])
    else:
        ocode, oerr = net.rpc("eth_getCode", [owner, block])
        if ocode is None:
            R.add("owner.owner", "Owner / admin", "unknown", f"{owner_src} = {owner}; eth_getCode on it failed ({oerr}), so wallet vs contract is unknown.",
                  [f"eth_call {a} {owner_src} @ {bn}", f"{c['explorer']}/address/{owner}"])
        elif ocode in ("0x", "0x0"):
            R.add("owner.owner", "Owner / admin", "flag", f"{owner_src} = {owner}, a plain wallet (no code): one key controls owner-only functions.",
                  [f"eth_call {a} {owner_src} @ {bn}", f"{c['explorer']}/address/{owner}"], "owner_eoa")
        elif is_7702(ocode):
            res["owner_7702_delegate"] = "0x" + ocode[8:48].lower()
            R.add("owner.owner", "Owner / admin", "flag",
                  f"{owner_src} = {owner}, a plain wallet with an EIP-7702 delegation to {'0x' + ocode[8:48].lower()} (code prefix 0xef0100), not a multisig or timelock: one key controls owner-only functions.",
                  [f"eth_call {a} {owner_src} @ {bn}", f"eth_getCode({owner}) = {ocode[:10]}… (EIP-7702 delegation designator)", f"{c['explorer']}/address/{owner}"], "owner_eoa")
        else:
            R.add("owner.owner", "Owner / admin", "flag", f"{owner_src} = {owner}, a contract (multisig/timelock/factory - not further classified).",
                  [f"eth_call {a} {owner_src} @ {bn}", f"{c['explorer']}/address/{owner}"], "owner_contract")
    res["owner"] = owner

    # 5. privileged functions -------------------------------------------------------------
    found = {}  # cat -> set(sig)
    src_used = []
    for ab, lbl in ((abi, "verified ABI"), (impl_abi, "implementation ABI")):
        if ab:
            src_used.append(lbl)
            for f in ab:
                if f.get("type") != "function" or f.get("stateMutability") in ("view", "pure"): continue
                sig = f"{f['name']}({','.join(i['type'] for i in f.get('inputs', []))})"
                for cat, rx in NAME_RX.items():
                    if re.search(rx, f["name"], re.I): found.setdefault(cat, set()).add(sig + f" [{lbl}]")
    for cd, lbl in ((code, "runtime bytecode"), (impl_code, "implementation bytecode")):
        if cd and cd != "0x":
            src_used.append(lbl)
            for s in push4_selectors(cd) & set(SEL_TO_SIG):
                cat, sig = SEL_TO_SIG[s]; found.setdefault(cat, set()).add(f"{sig} {s} [{lbl}]")
    if not src_used:
        R.add("fn.scan", "Privileged functions", "unknown", "No ABI and no bytecode available.")
    else:
        fac = OWNER_RENOUNCED_FACTOR if renounced else 1.0
        for cat in ("fn_mint", "fn_blacklist", "fn_pause", "fn_fee_setter", "fn_trading_switch", "fn_withdraw", "fn_upgrade"):
            if cat in found:
                sigs = sorted(found[cat])
                note = " Owner is renounced, so points are halved (functions may still be callable by other roles)." if renounced else ""
                R.add(f"fn.{cat[3:]}", f"{FN_LABEL[cat]} function present", "flag",
                      f"Found {FN_LABEL[cat]} function(s): {', '.join(sigs[:4])}{' …' if len(sigs) > 4 else ''}.{note}",
                      [sfy_link if abi else f"selector scan of eth_getCode @ {bn}", exp_addr], points=WEIGHTS[cat] * fac)
        if not any(k in found for k in WEIGHTS if k.startswith("fn_")):
            R.add("fn.scan", "Privileged functions", "pass",
                  f"No mint/pause/blacklist/fee-setter/withdraw/upgrade selectors found in {', '.join(src_used)} (exact-signature list of {len(SEL_TO_SIG)} + ABI name patterns).",
                  [f"selector scan @ {bn}", sfy_link if abi else None])
        if not abi and not impl_abi:
            R.checks[-1]["detail"] += " Note: bytecode-only scan matches exact common signatures; renamed functions can be missed."

    # 6. GoPlus + honeypot.is (pattern reused from token-launch-scan) -------------------------
    gp_url = f"https://api.gopluslabs.io/api/v1/token_security/{c['goplus']}?contract_addresses={a}"
    gp = None
    if is_token:
        d, e = net.get(gp_url)
        gp = ((d or {}).get("result") or {}).get(a) if d else None
        res["goplus"] = gp
        if gp is None or "is_honeypot" not in gp and "is_mintable" not in gp:
            R.add("trade.goplus", "GoPlus token security", "unknown", f"GoPlus has no (or partial) data for this token yet{(': ' + e) if e else ''}.", [gp_url])
        else:
            if gp.get("is_honeypot") == "1":
                R.add("trade.honeypot", "Honeypot check", "flag", "GoPlus is_honeypot=1 (sells may fail).", [gp_url], "honeypot")
            gflags = [k for k in ("cannot_sell_all", "transfer_pausable", "hidden_owner", "can_take_back_ownership", "owner_change_balance",
                                  "selfdestruct", "slippage_modifiable", "personal_slippage_modifiable", "is_blacklisted", "is_mintable") if gp.get(k) == "1"]
            if gflags:
                R.add("trade.goplus", "GoPlus token security", "flag", "GoPlus flags: " + ", ".join(gflags) + ".", [gp_url], "goplus_flag")
            else:
                R.add("trade.goplus", "GoPlus token security", "pass", "GoPlus: no honeypot/mint/pause/blacklist/hidden-owner flags.", [gp_url])
            for t in ("buy_tax", "sell_tax"):
                try:
                    if gp.get(t) not in (None, "") and float(gp[t]) > 0.10:
                        R.add(f"trade.{t}", f"{t.replace('_', ' ')}", "flag", f"GoPlus {t} = {float(gp[t]) * 100:.1f}%.", [gp_url], "high_tax")
                except ValueError: pass
            if gp.get("honeypot_with_same_creator") == "1":
                R.add("trade.creator_hp", "Creator history", "flag", "GoPlus honeypot_with_same_creator=1.", [gp_url], "same_creator_honeypot")
            if gp.get("creator_address") and not creation["deployer"]:
                creation.update(deployer=gp["creator_address"].lower(), source="GoPlus creator_address")
    if is_token and c["honeypot"]:
        hp_url = f"https://api.honeypot.is/v2/IsHoneypot?address={a}&chainID={c['honeypot']}"
        h, e = net.get(hp_url)
        if h and h.get("simulationSuccess"):
            hr = h.get("honeypotResult") or {}; sim = h.get("simulationResult") or {}
            if hr.get("isHoneypot"):
                R.add("trade.sim", "Buy/sell simulation", "flag", f"honeypot.is simulation: honeypot ({hr.get('honeypotReason')}).", [hp_url], "honeypot")
            else:
                bt, st = sim.get("buyTax"), sim.get("sellTax")
                if (st or 0) > 10 or (bt or 0) > 10:
                    R.add("trade.sim", "Buy/sell simulation", "flag", f"honeypot.is simulated buy tax {bt}%, sell tax {st}%.", [hp_url], "high_tax")
                else:
                    R.add("trade.sim", "Buy/sell simulation", "pass", f"honeypot.is simulated sell OK; buy tax {bt}%, sell tax {st}%.", [hp_url])
        else:
            R.add("trade.sim", "Buy/sell simulation", "unknown", f"honeypot.is could not simulate ({e or (h or {}).get('summary') or 'no pair'}).", [hp_url])
    elif is_token:
        R.add("trade.sim", "Buy/sell simulation", "unknown", f"No free sell-simulation service supports {c['name']} (honeypot.is chain list).", [])

    # launch tx via first mint log when creation unknown
    if is_token and not creation["tx"] and bn:
        span = c["logs_span"]; frm = max(0, bn - span); tries = 1 if chain == "robinhood" else 30
        for _ in range(tries):
            logs, e = net.rpc("eth_getLogs", [{"fromBlock": hex(frm), "toBlock": hex(min(bn, frm + span)), "address": a,
                                               "topics": [TRANSFER, "0x" + "0" * 64]}], urls=[c["logs_rpc"]])
            if logs:
                creation.update(tx=logs[0]["transactionHash"], block=int(logs[0]["blockNumber"], 16), source="first mint Transfer log"); break
            frm -= span
            if frm < 0: break
    if creation["tx"]:
        tx, _ = net.rpc("eth_getTransactionByHash", [creation["tx"]])
        if tx:
            creation["tx_from"] = tx["from"].lower(); creation["tx_to"] = (tx.get("to") or "").lower() or None
            if not creation.get("block"): creation["block"] = int(tx["blockNumber"], 16)
    if creation.get("block"):
        creation["ts"] = blk_ts(hex(creation["block"]))
    res["creation"] = creation
    if creation.get("tx_to") in ENTRYPOINTS:
        creation["note"] = "creation tx went through an ERC-4337 EntryPoint; tx.from is a bundler, so the creator/smart account is used"
        creation["tx_from"] = None
    launcher = creation.get("tx_from") or creation.get("deployer")

    # 5b. can anyone use the privileged functions? (cheap role-holder check) ------------------
    fn_flags = [ch for ch in R.checks if ch["id"].startswith("fn.") and ch["id"] != "fn.scan" and ch["status"] == "flag"]
    if fn_flags and (owner is None or renounced):
        down, note, rev = role_check(net, a, block, bn, [abi, impl_abi], [code, impl_code], creation, owner)
        res["role_check"] = {"downgraded": down, "note": note.strip()}
        for ch in fn_flags:
            if down:
                ch["detail"] = ch["detail"].replace(" Owner is renounced, so points are halved (functions may still be callable by other roles).", " Owner is renounced.")
                ch.update(status="info", points=0); ch["detail"] += note
                ch["evidence"] = ch["evidence"] + [e for e in rev if e and e not in ch["evidence"]]
            else:
                ch["detail"] += " Role check: " + note

    # 7. supply held by launcher -----------------------------------------------------------
    if is_token and launcher and tok.get("totalSupply"):
        r, _ = call(net, a, "0x70a08231" + "0" * 24 + launcher[2:], block)
        if r:
            pct = int(r, 16) * 100 / tok["totalSupply"] if tok["totalSupply"] else 0
            st = "flag" if pct >= 5 else "pass"
            R.add("holders.launcher", "Launcher wallet supply share", st, f"Launch wallet {launcher} holds {pct:.2f}% of supply.",
                  [f"eth_call balanceOf({launcher}) @ {bn}", f"{c['explorer']}/address/{launcher}"], "launcher_holds_supply")

    # 7b. holder concentration (Blockscout token holders) -------------------------------
    pool_addrs = set()
    if is_token:
        th_url = f"{c['blockscout_api']}/tokens/{address}/holders"
        th, e = net.get(th_url)
        if th and th.get("items") is not None and tok.get("totalSupply"):
            tsup = tok["totalSupply"]; big = []
            for it in th["items"][:20]:
                h_ = it["address"]["hash"].lower(); pct = int(it["value"]) * 100 / tsup
                if h_ in DEAD: continue
                if it["address"].get("is_contract"):
                    hc, _ = net.rpc("eth_getCode", [h_, block])
                    if not is_7702(hc): continue  # pools/vaults/curves excluded; EIP-7702 delegated wallets kept
                big.append((h_, pct))
            top = big[0] if big else None
            ev = [th_url, f"{c['explorer']}/token/{address}?tab=holders"]
            if top and top[1] >= 10:
                R.add("holders.concentration", "Holder concentration", "flag",
                      f"Largest non-contract holder {top[0]} has {top[1]:.1f}% of supply (contracts such as pools/vaults excluded).", ev, "holder_concentration")
            elif top:
                R.add("holders.concentration", "Holder concentration", "pass", f"Largest non-contract holder has {top[1]:.2f}% of supply.", ev)
            else:
                R.add("holders.concentration", "Holder concentration", "info", "All indexed top holders are contracts (pool/curve/vault).", ev)
        else:
            R.add("holders.concentration", "Holder concentration", "unknown", f"Blockscout holders unavailable ({e or 'not indexed'}).", [th_url])

    # 8. liquidity + lock ---------------------------------------------------------------------
    ds_url = f"https://api.dexscreener.com/token-pairs/v1/{c['dexscreener']}/{a}"
    pairs, e = net.get(ds_url) if is_token else (None, "not a token")
    site_from_ds = None
    gt_url = f"https://api.geckoterminal.com/api/v2/networks/{c['gecko']}/tokens/{a}/pools"
    g, ge = net.get(gt_url) if is_token else (None, None)
    gt_top = max([float(p["attributes"].get("reserve_in_usd") or 0) for p in (g or {}).get("data", [])] or [None]) if g and g.get("data") else None
    ds_top = max([((p.get("liquidity") or {}).get("usd") or 0) for p in pairs] or [None]) if isinstance(pairs, list) and pairs else None
    res["liquidity_sources"] = {"dexscreener_top_usd": ds_top, "geckoterminal_top_usd": gt_top}
    disagree = ds_top is not None and gt_top is not None and max(ds_top, gt_top) > 5 * max(min(ds_top, gt_top), 1) and max(ds_top, gt_top) > 5000
    if is_token and isinstance(pairs, list) and not pairs:
        if g and g.get("data"):
            ds_url = gt_url
            pairs = [{"dexId": (p["relationships"]["dex"]["data"]["id"]), "pairAddress": p["attributes"]["address"],
                      "liquidity": {"usd": float(p["attributes"]["reserve_in_usd"]) if p["attributes"].get("reserve_in_usd") else None},
                      "pairCreatedAt": p["attributes"].get("pool_created_at"),
                      "url": f"https://www.geckoterminal.com/{c['gecko']}/pools/{p['attributes']['address']}",
                      "quoteToken": {"symbol": p["attributes"]["name"].split(" / ")[-1]}} for p in g["data"]]
    if is_token and isinstance(pairs, list):
        pairs = sorted(pairs, key=lambda p: -((p.get("liquidity") or {}).get("usd") or 0))
        res["pairs"] = [{"dex": p.get("dexId"), "pair": p.get("pairAddress"), "liq_usd": (p.get("liquidity") or {}).get("usd"),
                         "created": p.get("pairCreatedAt"), "url": p.get("url"), "quote": (p.get("quoteToken") or {}).get("symbol")} for p in pairs[:5]]
        for p in pairs:
            for w in ((p.get("info") or {}).get("websites") or []):
                site_from_ds = site_from_ds or w.get("url")
        if not pairs:
            R.add("liq.pool", "DEX liquidity", "flag", "Neither DexScreener nor GeckoTerminal lists a pool for this token.", [ds_url], "no_pool")
        else:
            top = pairs[0]; liq = (top.get("liquidity") or {}).get("usd")
            ev = [top.get("url"), ds_url]
            if disagree:
                R.add("liq.pool", "DEX liquidity", "unknown",
                      f"Sources disagree: DexScreener top pool ${ds_top:,.0f}, GeckoTerminal top pool ${gt_top:,.0f}. Not scored until they agree.", ev + [gt_url])
            elif liq is None:
                R.add("liq.pool", "DEX liquidity", "unknown", f"Top pool {top.get('dexId')} has no liquidity figure on DexScreener.", ev)
            elif liq < 5000:
                R.add("liq.pool", "DEX liquidity", "flag", f"Top pool liquidity ${liq:,.0f} ({top.get('dexId')}) - under $5k.", ev, "very_low_liquidity")
            elif liq < 25000:
                R.add("liq.pool", "DEX liquidity", "flag", f"Top pool liquidity ${liq:,.0f} ({top.get('dexId')}) - under $25k.", ev, "low_liquidity")
            else:
                R.add("liq.pool", "DEX liquidity", "pass", f"Top pool liquidity ${liq:,.0f} ({top.get('dexId')}).", ev)
            # lock status
            pa = (top.get("pairAddress") or "").lower(); dex = top.get("dexId") or ""
            lp_gp = [h for h in ((gp or {}).get("lp_holders") or [])]
            CUSTOM_LOCKER_NOTE = (" GoPlus may not recognise custom lockers, so its lock reading is not used as fact here."
                                  " Launch Watch does not analyse the locker's unlock terms or owner powers.")
            def fmt_lockers(L):
                return "; ".join(f"{x['name']} {x['address']} ({pct * 100:.1f}%, verified on {'/'.join(x['verified_on'])})" for x, pct in L)
            if lp_gp:
                def _pct(h):
                    try: return float(h.get("percent") or 0)
                    except ValueError: return 0.0
                gp_locked = sum(_pct(h) for h in lp_gp if str(h.get("is_locked")) == "1")
                burned = sum(_pct(h) for h in lp_gp if str(h.get("is_locked")) != "1" and (h.get("address") or "").lower() in DEAD)
                lockers = []
                if gp_locked + burned < 0.9:
                    cand = sorted([h for h in lp_gp if str(h.get("is_locked")) != "1" and (h.get("address") or "").lower() not in DEAD
                                   and str(h.get("is_contract")) == "1" and _pct(h) >= 0.01], key=lambda h: -_pct(h))[:5]
                    for h in cand:
                        li = locker_info(net, h["address"], block)
                        if li: lockers.append((li, _pct(h)))
                lk = sum(p_ for _, p_ in lockers)
                lev = [gp_url] + [f"{c['explorer']}/address/{x['address']}?tab=contract" for x, _ in lockers]
                if gp_locked + burned >= 0.9:
                    R.add("liq.lock", "LP lock / burn", "pass", f"GoPlus LP holders: {(gp_locked + burned) * 100:.1f}% locked or burned.", [gp_url])
                elif gp_locked + burned + lk >= 0.9:
                    R.add("liq.lock", "LP lock / burn", "info",
                          f"GoPlus reports {gp_locked * 100:.1f}% locked" + (f" and {burned * 100:.1f}% burned" if burned else "") +
                          f", but the LP position is held by verified locker contract(s): {fmt_lockers(lockers)}. Not scored as unlocked." + CUSTOM_LOCKER_NOTE, lev)
                else:
                    R.add("liq.lock", "LP lock / burn", "flag",
                          f"GoPlus LP holders: {(gp_locked + burned) * 100:.1f}% locked or burned" +
                          (f"; another {lk * 100:.1f}% sits in verified locker(s) {fmt_lockers(lockers)}, still under 90% in total." if lockers else
                           "; no verified locker contract holds the rest.") , lev, "lp_unlocked")
            elif len(pa) == 42:
                ts_, _ = call(net, pa, "0x18160ddd", block); t0, _ = call(net, pa, "0x0dfe1681", block)
                if ts_ and t0 and int(ts_, 16) > 0:
                    tot = int(ts_, 16); burned = 0
                    for d_ in DEAD:
                        r, _ = call(net, pa, "0x70a08231" + "0" * 24 + d_[2:], block)
                        burned += int(r, 16) if r else 0
                    pct = burned * 100 / tot
                    pev = [f"eth_call {pa} totalSupply()/balanceOf(dead) @ {bn}", f"{c['explorer']}/address/{pa}"]
                    lockers, lk_note = [], " Third-party lockers could not be checked (Blockscout LP-token holders unavailable)."
                    if pct < 90:
                        lh_url = f"{c['blockscout_api']}/tokens/{pa}/holders"
                        lh, lhe = net.get(lh_url)
                        if lh and lh.get("items") is not None:
                            lk_note = ""
                            for it in lh["items"][:10]:
                                h_ = it["address"]["hash"].lower()
                                if h_ in DEAD or not it["address"].get("is_contract"): continue
                                bal, _ = call(net, pa, "0x70a08231" + "0" * 24 + h_[2:], block)  # pinned on-chain balance
                                share = int(bal, 16) / tot if bal else 0
                                if share < 0.01: continue
                                li = locker_info(net, h_, block)
                                if li: lockers.append((li, share))
                            pev.append(lh_url)
                    lk = sum(p_ for _, p_ in lockers) * 100
                    pev += [f"{c['explorer']}/address/{x['address']}?tab=contract" for x, _ in lockers]
                    if pct >= 90:
                        R.add("liq.lock", "LP lock / burn", "pass", f"V2-style pair {pa}: {pct:.1f}% of LP tokens burned (0x0/dead).", pev)
                    elif pct + lk >= 90:
                        R.add("liq.lock", "LP lock / burn", "info",
                              f"V2-style pair {pa}: {pct:.1f}% of LP tokens burned and {lk:.1f}% held by verified locker contract(s): {fmt_lockers(lockers)}. Not scored as unlocked."
                              " Launch Watch does not analyse the locker's unlock terms or owner powers.", pev)
                    else:
                        R.add("liq.lock", "LP lock / burn", "flag",
                              f"V2-style pair {pa}: {pct:.1f}% of LP tokens burned (0x0/dead)" +
                              (f", {lk:.1f}% in verified locker(s) {fmt_lockers(lockers)}" if lockers else (", no verified locker contract among the top LP holders" if not lk_note else "")) +
                              "." + lk_note, pev, "lp_unlocked")
                else:
                    R.add("liq.lock", "LP lock / burn", "unknown", f"Pool {pa} ({dex}) is not an ERC-20 LP pair (bonding curve / concentrated liquidity); lock status not readable from free sources.",
                          [f"{c['explorer']}/address/{pa}"])
            else:
                R.add("liq.lock", "LP lock / burn", "unknown", f"Pool is {dex} (v4 pool id {pa[:12]}…): liquidity sits in position NFTs; lock status not readable from free sources.", [top.get("url")])
    elif is_token:
        R.add("liq.pool", "DEX liquidity", "unknown", f"DexScreener request failed: {e}.", [ds_url])

    # 9. deployer / launcher -----------------------------------------------------------------
    if launcher:
        nonce_hex, _ = net.rpc("eth_getTransactionCount", [launcher, block])
        lcode, _ = net.rpc("eth_getCode", [launcher, block])
        role = "launch-tx sender" if creation.get("tx_from") else "deployer"
        ev = [f"{c['explorer']}/address/{launcher}", f"{c['explorer']}/tx/{creation['tx']}" if creation.get("tx") else None]
        if lcode and lcode != "0x" and not is_7702(lcode):
            R.add("deployer.type", "Deployer", "info", f"{role} {launcher} is a contract (factory); wallet history not applicable.", ev)
        elif nonce_hex is not None:
            nonce = int(nonce_hex, 16); res["launcher_nonce"] = nonce
            if nonce <= 5:
                R.add("deployer.fresh", "Deployer wallet history", "flag", f"{role} {launcher} has sent only {nonce} transaction(s) in total (fresh wallet).",
                      ev + [f"eth_getTransactionCount({launcher}) @ {bn} = {nonce}"], "fresh_deployer")
            # contracts created directly (CREATE from EOA nonces)
            if nonce <= 400:
                addrs = [create_addr(launcher, n) for n in range(nonce)]
                codes = net.batch_code(addrs, block)
                made = [x for x in addrs if codes.get(x) and codes[x] != "0x"]
                res["deployer_contracts"] = made
                st = "flag" if len(made) >= 10 else "info"
                R.add("deployer.contracts", "Contracts deployed by this wallet", st,
                      f"{len(made)} live contract(s) created directly by {launcher} (CREATE nonce scan 0..{nonce - 1}); tokens launched via factories are not counted. Wallet nonce = {nonce}.",
                      ev + [f"{c['explorer']}/address/{x}" for x in made[:3]], "serial_deployer")
            else:
                R.add("deployer.contracts", "Contracts deployed by this wallet", "flag",
                      f"{launcher} has sent {nonce} transactions (>400; nonce scan skipped). High-volume wallet.", ev + [f"eth_getTransactionCount = {nonce}"], "serial_deployer")
            # age
            bst, bst_err = net.get(f"{c['blockscout_api']}/addresses/{launcher}/transactions?sort=block_number&order=asc")
            items = (bst or {}).get("items") or []
            made_bs = sorted({(i.get("created_contract") or {}).get("hash", "").lower() for i in items if i.get("created_contract")} - {""})
            if made_bs: res["deployer_contracts_blockscout_page1"] = made_bs
            age_done = False
            if items:
                first = min(items, key=lambda i: i.get("block_number") or 10**12)
                ts = dt.datetime.fromisoformat(first["timestamp"].replace("Z", "+00:00"))
                age_d = (now - ts).total_seconds() / 86400
                if True:  # list is sorted ascending server-side (verified 2026-10-14), so items[0] is the oldest
                    st = "flag" if age_d < 7 else "pass"
                    R.add("deployer.age", "Deployer wallet age", st,
                          f"Oldest transaction of {launcher} on Blockscout: block {first['block_number']} ({ts:%Y-%m-%d %H:%M} UTC), {age_d:.1f} days before scan."
                          ,
                          ev + [f"{c['explorer']}/tx/{first['hash']}", f"{c['blockscout_api']}/addresses/{launcher}/transactions?sort=block_number&order=asc"], "young_deployer")
                    age_done = True
            if age_done:
                pass
            elif c["archive_rpcs"] and nonce > 0 and bn:
                lo, hi = 0, bn; ok = True
                while lo < hi:
                    mid = (lo + hi) // 2
                    net.archive_call = True
                    v, e = net.rpc("eth_getTransactionCount", [launcher, hex(mid)], urls=c["archive_rpcs"])
                    net.archive_call = False
                    if v is None: ok = False; break
                    if int(v, 16) > 0: hi = mid
                    else: lo = mid + 1
                if ok:
                    ts = blk_ts(hex(lo)); age_d = (now.timestamp() - ts) / 86400 if ts else None
                    if age_d is not None:
                        st = "flag" if age_d < 7 else "pass"
                        R.add("deployer.age", "Deployer wallet age", st, f"First outgoing tx from {launcher} in block {lo} ({dt.datetime.fromtimestamp(ts, dt.timezone.utc):%Y-%m-%d %H:%M} UTC), {age_d:.1f} days ago.",
                              ev + [f"{c['explorer']}/block/{lo}", "archive eth_getTransactionCount binary search"], "young_deployer")
                else:
                    R.add("deployer.age", "Deployer wallet age", "unknown", f"Archive RPC failed during age search: {e}.", ev)
            else:
                R.add("deployer.age", "Deployer wallet age", "unknown",
                      f"Blockscout tx history unavailable ({bst_err or 'no transactions indexed yet'}) and {c['name']} public RPC keeps only recent state (no archive).", ev)
    else:
        R.add("deployer.fresh", "Deployer wallet history", "unknown", "Deployer/launcher not identified (unverified non-token contract, no Sourcify deployment, no mint log).", [exp_addr])

    # 10. site hosting / IP overlap ------------------------------------------------------------
    site = site or site_from_ds
    res["site"] = site
    clusters = json.load(open(os.path.join(HERE, "data", "clusters.json")))
    if site:
        host = urllib.parse.urlparse(site if "://" in site else "https://" + site).hostname
        doh = f"https://dns.google/resolve?name={host}&type=A"
        d, e = net.get(doh)
        ips = sorted({x["data"] for x in (d or {}).get("Answer", []) if x.get("type") == 1}) if d else []
        res["site_ips"] = ips
        if not ips:
            R.add("host.ip", "Site hosting overlap", "unknown", f"{host}: no A record via Google DoH ({e or 'NXDOMAIN/empty'}).", [doh])
        else:
            shared = [ip for ip in ips if any(ip.startswith(p) for v in clusters["shared_cdn_prefixes"].values() if isinstance(v, list) for p in v)]
            hit = sub = None
            for cl in clusters["clusters"]:
                if set(ips) & set(cl["ips"]): hit = cl
                elif any(ip.rsplit(".", 1)[0] == x.rsplit(".", 1)[0] for ip in ips for x in cl["ips"]) and not shared: sub = cl
            same = [m_["project"] for m_ in (hit or {}).get("members", []) if m_["domain"] != host]
            if hit:
                R.add("host.ip", "Site hosting overlap", "flag",
                      f"{host} resolves to {', '.join(ips)}, the same server as watchlist cluster '{hit['id']}' ({hit['label']}), shared with: {', '.join(same)}. Seed: {hit['seed_source']}.",
                      [doh, "https://ipinfo.io/" + hit["ips"][0]], "hosting_cluster")
            elif sub:
                R.add("host.ip", "Site hosting overlap", "flag", f"{host} resolves to {', '.join(ips)}, same /24 as watchlist cluster '{sub['id']}'.", [doh], "hosting_cluster_subnet")
            elif shared:
                R.add("host.ip", "Site hosting overlap", "info", f"{host} -> {', '.join(ips)} (shared CDN/PaaS range; IP overlap not meaningful). No watchlist match.", [doh])
            else:
                R.add("host.ip", "Site hosting overlap", "pass", f"{host} -> {', '.join(ips)}; no watchlist match.", [doh])
        # domain age via RDAP
        apex = ".".join(host.split(".")[-2:])
        rd_url = f"https://rdap.org/domain/{apex}"
        platform = host.lower().endswith(PLATFORM_SUFFIXES)
        rd, e = net.get(rd_url) if not platform else (None, None)
        reg = None
        for ev_ in (rd or {}).get("events", []):
            if ev_.get("eventAction") == "registration": reg = ev_.get("eventDate")
        if platform:
            R.add("host.domain_age", "Domain age", "info", f"{host} is a subdomain on a shared site-builder/PaaS ({apex}); domain age does not apply. No domain was bought for this project.", [])
        elif reg:
            age = (now - dt.datetime.fromisoformat(reg.replace("Z", "+00:00"))).total_seconds() / 86400
            R.add("host.domain_age", "Domain age", "flag" if age < 14 else "pass", f"{apex} registered {reg[:10]} ({age:.0f} days ago).", [rd_url], "young_domain")
        else:
            R.add("host.domain_age", "Domain age", "unknown", f"RDAP gave no registration date for {apex} ({e or 'field missing'}).", [rd_url])
    else:
        R.add("host.ip", "Site hosting overlap", "unknown", "No project website known (none passed, none on DexScreener).", [])

    if x_created:
        try:
            age = (now - dt.datetime.fromisoformat(x_created.replace("Z", "+00:00"))).total_seconds() / 86400
            R.add("social.x_age", "Launch X account age", "flag" if age < 3 else "pass", f"X account created {x_created[:10]} ({age:.1f} days before scan).",
                  [post], "young_x_account")
        except ValueError: pass

    res["http_log"] = net.log; res["rpc_pin_fallbacks_to_latest"] = net.pin_fallbacks
    return finalize(res, R)

def finalize(res, R):
    total = min(100, round(sum(ch["points"] for ch in R.checks)))
    res["checks"] = R.checks; res["score"] = total
    res["band"] = "HIGH" if total >= 75 else "ELEVATED" if total >= 50 else "MODERATE" if total >= 25 else "LOW"
    res["coverage"] = {"run": sum(1 for ch in R.checks if ch["status"] != "unknown"), "unknown": sum(1 for ch in R.checks if ch["status"] == "unknown")}
    res["top_reasons"] = [ch for ch in sorted(R.checks, key=lambda x: (-x["points"], x["id"])) if ch["points"] > 0 and ch["status"] in ("flag", "unknown")][:3]
    return res

def to_md(r):
    t = r.get("token", {})
    nm = f"{t.get('name') or '?'} ({t.get('symbol') or '?'})" if t else "contract"
    L = [f"# Launch Watch: {nm} on {CHAINS[r['chain']]['name']}", "",
         f"- Address: `{r['address']}`", f"- Risk score: **{r['score']}/100 ({r['band']} risk signals)**",
         f"- Checks run: {r['coverage']['run']}, unknown: {r['coverage']['unknown']}", f"- Scanned: {r['scanned_at_utc']} at block {r['block']}",
         f"- Launch post: {r.get('post') or 'n/a'}", "", "| Status | Pts | Check | Detail | Evidence |", "|---|---|---|---|---|"]
    for ch in r["checks"]:
        L.append(f"| {ch['status']} | {ch['points']} | {ch['title']} | {ch['detail'].replace('|', '/')} | {' '.join(ch['evidence'][:3])} |")
    L += ["", "_Automated checks, not financial advice. A risk signal is not a finding of wrongdoing._"]
    return "\n".join(L)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--chain", required=True, choices=list(CHAINS)); ap.add_argument("--address", required=True)
    ap.add_argument("--site"); ap.add_argument("--post"); ap.add_argument("--x-created")
    ap.add_argument("--json", action="store_true"); ap.add_argument("--out"); ap.add_argument("--raw-dir")
    a = ap.parse_args()
    if not re.fullmatch(r"0x[0-9a-fA-F]{40}", a.address): sys.exit("address must be 0x + 40 hex")
    r = score(a.chain, a.address, a.site, a.post, a.x_created)
    if a.raw_dir:
        os.makedirs(a.raw_dir, exist_ok=True)
        json.dump(r, open(os.path.join(a.raw_dir, f"{a.chain}-{a.address.lower()}.json"), "w"), indent=1)
    out = json.dumps(r, indent=1) if a.json else to_md(r)
    print(out)
    if a.out: open(a.out, "w").write(out)

if __name__ == "__main__":
    main()
