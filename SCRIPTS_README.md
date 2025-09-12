## How to use these test scripts

- Fast local checks (lint + unit tests):

```bash
bash scripts/test_fast.sh
```

- Full suite (unit + integration):

```bash
bash scripts/test_full.sh
```

- Performance smoke (10k synthetic packets):

```bash
python scripts/perf_10k.py
```

> Note: Tests that require live capture (Scapy) are auto-skipped unless Scapy is installed.