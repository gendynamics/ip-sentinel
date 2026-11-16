# ip-sentinel

IP Sentinel — local-only cryptographic evidence vault for the UGREEN AI NAS hackathon. SHA-256 hashing, hash-chained custody log, verify-before-trust export, two-tier approval gates. Rust core + Uliya skill package.

## Working prototype

[`prototype/`](prototype/) is a runnable Python version of the custody engine with a local web dashboard. You scan a folder, review a preview, confirm, and commit hash-linked blocks. You can then prove a file against the ledger, run an integrity audit, and export a verification package that a third party can check offline. The dashboard listens on 127.0.0.1 only. The prototype runs on any machine with Python 3.9+ and no extra packages. It does not call the UGREEN NAS tools yet.

```sh
cd prototype
python3 -m unittest        # engine tests
python3 sentinel_gui.py    # opens the dashboard in your browser
```

[`prototype/DEMO_SCRIPT.md`](prototype/DEMO_SCRIPT.md) is the run sheet for the demo video.
