"""Offline-ish tests for bot/paid_scan.py. Network: mempool.space (read-only). Run: python3 tests/test_bot.py [txid]"""
import json, os, sys, urllib.request
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bot"))
import paid_scan as P

def t_parse():
    body = "### Chain\n\nRobinhood Chain (chain ID 4663)\n\n### Contract address\n\n0x8192a554fe2e371af32978cc18e04add26c641dc\n\n### BTC transaction ID\n\n_No response_\n\n### Acknowledgements\n\n- [X] ok"
    f = P.parse_form(body)
    assert f == {"chain": "Robinhood Chain (chain ID 4663)", "address": "0x8192a554fe2e371af32978cc18e04add26c641dc", "txid": "", "site": ""}, f
    assert P.CHAIN_OPTS[f["chain"].lower()] == "robinhood"

def t_coinjoin():
    cj = {"vin": [{}] * 6, "vout": [{"value": 5000000}] * 5 + [{"value": 123}]}
    assert P.coinjoin_like(cj) and not P.coinjoin_like({"vin": [{}] * 2, "vout": [{"value": 1}, {"value": 2}]})

def t_ledger():
    led = {}; pay = {"txid": "ab" * 32, "sats": 24500, "tier": "pack", "uses_allowed": 5}
    for n in range(1, 6):
        assert P.ledger_check(led, pay, n, "alice")[0]; e = P.ledger_record(led, pay, n, "alice"); P.set_claim(e, n, "done")
    ok, why = P.ledger_check(led, pay, 6, "alice"); assert not ok and "All 5" in why, why
    ok, why = P.ledger_check(led, pay, 7, "mallory"); assert not ok and "already used" in why, why
    assert P.ledger_check(led, pay, 3, "alice")[0]   # same issue re-check allowed
    single = {"txid": "cd" * 32, "sats": 6100, "tier": "single", "uses_allowed": 1}
    P.ledger_record(led, single, 10, "bob")
    assert not P.ledger_check(led, single, 11, "bob")[0]

def t_accept_path(txid):
    """Point PAY_ADDR at a real output of a confirmed mainnet tx to exercise the accept path end to end (read-only)."""
    tx = json.load(urllib.request.urlopen(f"https://mempool.space/api/tx/{txid}"))
    o = max((o for o in tx["vout"] if o.get("scriptpubkey_address")), key=lambda o: o["value"])
    save = (P.PAY_ADDR, P.SINGLE_MIN, P.PACK_MIN, P.PACK_MAX, P.NOT_BEFORE_UTC)
    P.PAY_ADDR, P.SINGLE_MIN, P.PACK_MIN, P.PACK_MAX = o["scriptpubkey_address"], 1, o["value"] * 10, o["value"] * 20
    P.NOT_BEFORE_UTC = P.dt.datetime(2009, 1, 3, tzinfo=P.dt.timezone.utc)
    try:
        r = P.check_payment(txid); print("accept-path (simulated recipient):", r["verdict"], r["reason"])
        assert r["verdict"] in ("ok", "mixer"), r
    finally:
        P.PAY_ADDR, P.SINGLE_MIN, P.PACK_MIN, P.PACK_MAX, P.NOT_BEFORE_UTC = save
    r = P.check_payment(txid); print("real address:", r["verdict"], r["reason"]); assert r["verdict"] == "invalid"

if __name__ == "__main__":
    t_parse(); t_coinjoin(); t_ledger(); print("parse/coinjoin/ledger: ok")
    if len(sys.argv) > 1: t_accept_path(sys.argv[1])
