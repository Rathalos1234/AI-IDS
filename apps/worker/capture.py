import os, random, time
from datetime import datetime
from core.bus import bus

USE_SCAPY = os.getenv("USE_SCAPY", "0") == "1"

#does actualy scan network traffic just generates random stuff (use scappy for actual network traffic)
def simulate_features():
    src_ip = f"10.0.0.{random.randint(2,200)}"
    syn_rate = max(0, int(random.gauss(5, 3)))
    if random.random() < 0.02:
        syn_rate = random.randint(120, 500)
    vec = {
        "ts": datetime.utcnow().isoformat(),
        "window_secs": 5,
        "src_ip": src_ip,
        "dst_ip": "192.168.1.10",
        "pkts": random.randint(50, 400),
        "bytes": random.randint(5_000, 500_000),
        "uniq_dsts": random.randint(1, 20),
        "uniq_dst_ports": random.randint(1, 100),
        "syn_rate": syn_rate,
        "rst_rate": max(0, int(random.gauss(2, 1))),
        "failed_auth_rate": max(0, int(random.gauss(1, 1))),
        "avg_len": random.uniform(200, 900),
    }
    return vec

def main():
    print("[capture] starting (simulator mode)" if not USE_SCAPY else "[capture] starting (scapy mode)")
    while True:
        vec = simulate_features()
        bus.publish("features", vec)
        time.sleep(0.5)

if __name__ == "__main__":
    main()
