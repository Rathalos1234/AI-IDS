# Test Plan — v1 (Sprint 1)

**Scope**  
Covers packet feature extraction, anomaly scoring, and alert formatting for running code & tests in demos.

**Risks**  
- False positives/negatives on rare protocols  
- Edge parsing (empty payloads, IPv6, odd ports)  
- Performance at ≥10k rows / packets  
- Robustness to corrupt packets / missing model fields

**Techniques chosen (and why)**  
- Unit (logic correctness, fast feedback)  
- Integration (packet → features → model → alert)  
- Property-flavored checks (ephemeral port predicate invariants)  
- Perf smoke (10k rows guardrail)  
- Fault-injection (graceful errors)

**Entry / Exit criteria**  
- Entry: build passes; model bundle loads; seed data available.  
- Exit (S1 targets):  
  - Unit & integration pass rate ≥ 95%  
  - Perf: 10k rows in ≤ **TODO: set target, e.g., 2.0s** and peak memory ≤ **TODO**  
  - No unhandled exceptions on corrupt packet paths  
  - Ephemeral-port predicate holds on randomized samples

**Traceability (feature ↔ test cases)**

| Feature / requirement                      | Method           | Test ID(s)                       |
|--------------------------------------------|------------------|----------------------------------|
| Extract features from IPv4/6 packets       | Unit             | PP-U-01, PP-U-02                 |
| Ephemeral port predicate correctness       | Property/unit    | PP-U-03                          |
| Deterministic scoring w/ fixed seed        | Unit             | AD-U-01                          |
| Severity mapping boundaries                 | Unit             | AD-U-02                          |
| End-to-end packet→alert                     | Integration      | INT-01                           |
| Corrupt/partial packet handling             | Fault-injection  | FE-01                             |
| 10k perf snapshot                           | Perf smoke       | PERF-10K-01                      |

**Planned data**  
- Synthetic packets (fixtures)  
- Minimal model bundle with fixed seed (fixture)

**Reporting**  
- Paste pytest summaries (fast + full) and perf snapshot every sprint.  
- Update this plan with added tests & tuned thresholds.
