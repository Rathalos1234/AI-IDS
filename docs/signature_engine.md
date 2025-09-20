# Signature Engine — Design Spec

## 1) Purpose & Scope

Provide fast, explainable detections that complement the anomaly model. The engine evaluates simple, readable rules against each engineered packet/flow record and emits `SIGNATURE:` hits with a severity that maps to log levels.

**Out‑of‑scope (Sprint 1):** external rule files, complex stateful correlation, and auto‑tuning.

---

## 2) Where it sits (Chain of Responsibility)

```
Packet Capture → Feature Engineering (PacketProcessor) → [SignatureEngine] → Anomaly Detector → Emit Alerts
```

- **Inputs:** latest engineered row (`dict`) and current sliding window (`DataFrame`).
- **Outputs:** zero or more `SignatureHit`s, each `{name, severity, description}`.
- **Merge policy:** signature hits always emit; anomaly hits emit based on model thresholds. Both share the same severity→log‑level mapping.

---

## 3) Public API (code‑based rules)

```python
@dataclass
class SigResult:
    name: str
    severity: str      # "low" | "medium" | "high"
    description: str

@dataclass
class Rule:
    name: str
    severity: str
    description: str
    match: Callable[[Dict, pandas.DataFrame], bool]

class SignatureEngine:
    def __init__(self, rules: List[Rule]): ...
    def evaluate(self, last_row: Dict, window_df: pd.DataFrame) -> List[SigResult]: ...

# factory: default rules
def default_engine() -> SignatureEngine: ...
```

**Invocation (inside monitor loop):**

```python
last_row = processed_df.tail(1).iloc[0].to_dict()
hits = sig_engine.evaluate(last_row, window_df)
for h in hits:
    log_signature(h, last_row)  # emits SIGNATURE: ...
```

---

## 4) Data the rules can use

From the engineered record/window:

- `src_ip`, `dest_ip`, `protocol`, `packet_size`, `dport`, `is_ephemeral_sport`
- `unique_dports_15s` (count of distinct dst ports by source over last 15s)
- `direction` (0=inbound, 1=outbound)
- Full `window_df` for context when needed

---

## 5) Default rules (Sprint 1)

1. `` *(high)*
   - **Logic:** flag when `unique_dports_15s ≥ T`.
   - **Default:** `T = 10`.
   - **Rationale:** many unique destination ports in a short window is a common scan pattern.
2. `` *(medium)*
   - **Logic:** `direction == 0` **and** `dport ∈ {22, 23, 2323, 3389, 5900}`.
   - **Rationale:** unsolicited inbound to sensitive services is suspicious.

**Example log lines**

```
SIGNATURE: port-scan-suspected severity=high | 192.0.2.10 -> 198.51.100.5 dport=55462 desc="Source contacted many unique destination ports over a short window."
SIGNATURE: inbound-sensitive-port severity=medium | 203.0.113.7 -> 192.0.2.5 dport=22 desc="Inbound traffic to a sensitive service port."
```

---

## 6) Logging & Severity semantics

- **Format:** `SIGNATURE: <name> severity=<sev> | <src> -> <dest> dport=<n> desc="..."`
- **Mapping to logger:** `high→ERROR`, `medium→WARNING`, `low→INFO` (same mapping used by anomaly alerts).
- **Dedup (recommended):** emit at most once per `(rule, src, dest)` within `DedupSeconds` to limit noise during scans.

---

## 7) Configuration (INI)

```
[Signatures]
Enable = true               # master toggle
PortScanThreshold = 10      # optional override (if present)
DedupSeconds = 5.0          # optional rate‑limit for repeated hits
SensitivePorts = 22,23,2323,3389,5900   # optional override
```

**Notes:** If a key is absent, sensible defaults are applied in code. In Sprint 1 we primarily honor `Enable`; others are safe extensions.

---

## 8) Performance considerations

- Rules must be **O(1)** over the current row or **O(k)** over the window where `k` is small (e.g., vectorized count already computed).
- Rule failures must be **non‑fatal**; exceptions are caught and skipped.

---

## 9) Security & safety

- Never block traffic directly in Sprint 1; this system **only logs**.
- Avoid PII leakage in logs beyond IPs/ports already captured.
- Configurable thresholds prevent overly noisy alerts in typical LAN traffic.

---

