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

  # Preferred (asserts budgets + saves a one-line snapshot)
  # This is also already included in the test_full.sh script
  pytest -m perf -k 10k -s | tee sprint_artifacts/pytest_perf.txt
  
  # Legacy option:
  # python3 scripts/perf_10k.py

**Artifacts:** the scripts write summaries to `sprint_artifacts/`