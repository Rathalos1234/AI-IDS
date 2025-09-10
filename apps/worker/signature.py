import yaml
from datetime import datetime
from core.bus import bus

def load_rules(path="rules/builtin.yaml"):
    with open(path, "r") as f:
        return yaml.safe_load(f)

rules = load_rules()

def eval_rules(feat):
    fires = []
    for r in rules:
        cond = r.get("when", {})
        ok = True
        if "syn_rate_gt" in cond and not (feat.get("syn_rate",0) > cond["syn_rate_gt"]): ok = False
        if "failed_auth_rate_gt" in cond and not (feat.get("failed_auth_rate",0) > cond["failed_auth_rate_gt"]): ok = False
        if "uniq_dst_ports_gt" in cond and not (feat.get("uniq_dst_ports",0) > cond["uniq_dst_ports_gt"]): ok = False
        if ok:
            fires.append({
                "ts": datetime.utcnow().isoformat(),
                "src_ip": feat["src_ip"],
                "kind": "signature",
                "label": r.get("label","rule"),
                "score": 1.0,
                "severity": r.get("severity","low"),
                "details": {"rule_id": r.get("id")}
            })
    return fires

def main():
    print("[signature] waiting for features...]")
    for _, feat in bus.consume("features", group="sig-g", consumer="sig-1"):
        for det in eval_rules(feat):
            bus.publish("detections", det)

if __name__ == "__main__":
    main()
