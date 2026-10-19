# Launch Watch instant scan ($5 in BTC)

Pay-per-scan automated risk reports for **Robinhood Chain (4663)** and **Base (8453)** contracts, from
[Metatron Launch Watch](https://invisiblemonsters.github.io/launch-watch/). Runs entirely on GitHub Actions:
open an issue, pay in BTC, get the report as a comment.

**[Order an instant scan](https://github.com/invisiblemonsters/launch-watch-scan/issues/new?template=paid-scan.yml)**

| Tier | Price | Accepted range |
|---|---|---|
| Instant scan | **6,100 sats** ($5) | 5,490 - 22,049 sats = 1 scan |
| Scan pack | **24,500 sats** ($20) | 22,050 - 26,950 sats = 5 scans, same GitHub account |

Prices use a **fixed rate of $81,771/BTC** (mempool.space, 2026-10-19); they do not float with the market.
Payment address (the only one): **`bc1qk43phw0cl63a2pqxssnakwsnuxu0swwjvmm9r0`**, the same as on the
[Get reviewed](https://invisiblemonsters.github.io/launch-watch/get-reviewed.html) page.

## How it works

1. The issue form (label `paid-scan`) asks for the chain, the contract address, an optional website and the BTC txid.
2. [`.github/workflows/paid-scan.yml`](.github/workflows/paid-scan.yml) runs on issue opened/edited/reopened and every 15 minutes.
   [`bot/paid_scan.py`](bot/paid_scan.py):
   - validates the chain and address;
   - checks the txid on the public mempool.space API: it pays the address above, the amount is in range,
     it has at least 1 confirmation, and it is not in [`ledger/used-txids.json`](ledger/used-txids.json) (committed by the bot);
   - unconfirmed: comments *waiting for confirmation* once, labels `awaiting-confirmation`, and re-checks every 15 minutes;
   - invalid: explains why (`payment-invalid`); edit the issue with a corrected txid to re-run;
   - runs the vendored scanner ([`scanner/score.py`](scanner/score.py), Launch Watch scorer v0.2.0) and posts the
     score, band, every check and its evidence link, then labels the issue `scanned` + band and closes it.
3. Payments through mixers/CoinJoin, and launches in excluded hosting clusters, are declined politely and labelled
   `refund-due` for a **manual** refund. Nothing is refunded automatically.

Reports contain the same automated risk signals as the public Launch Watch pages. They are **not audits or
guarantees**, not financial advice, and a risk signal is not evidence of wrongdoing. Never post vulnerabilities in an
issue: use [private vulnerability reporting](https://github.com/invisiblemonsters/launch-watch/security/advisories/new).

Need a person to look? [$50 Verified badge or $150 24h review](https://invisiblemonsters.github.io/launch-watch/get-reviewed.html).

## Local dry runs

```bash
pip install "pycryptodome>=3.20,<4"
python3 bot/paid_scan.py --check-tx <txid>                 # payment verdict only, no writes
python3 bot/paid_scan.py --scan robinhood 0x...             # print a report comment, no writes
python3 tests/test_bot.py <some-confirmed-mainnet-txid>    # parser, ledger, CoinJoin and payment-path tests
```

## Limits

- First valid claim wins: payments to a public address are visible to everyone, so a txid is bound to the GitHub
  account that first submits it. Disputes are handled by the maintainer in the issue.
- Scheduled runs on GitHub can start late under load, and GitHub pauses schedules in repos with no activity for 60 days.
- Public explorers/APIs (Blockscout, GoPlus, DexScreener) can rate-limit runner IPs; affected checks show as `unknown`.

MIT licensed. Scanner reuses the GoPlus/honeypot.is pattern from
[token-launch-scan](https://github.com/invisiblemonsters/token-launch-scan) (MIT, see `scanner/LICENSE-token-launch-scan`).
