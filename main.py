import scapy.all as scapy
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import datetime
import matplotlib.pyplot as plt
from collections import deque
import argparse
import tabulate
import netifaces
import os
from typing import Optional, Tuple
from scipy.stats import entropy

# Global deque to store packet data with a configurable size
DEFAULT_WINDOW_SIZE = 1000
packet_data = deque(maxlen=DEFAULT_WINDOW_SIZE)


def validate_interface(interface: str) -> None:
    """Validate if the network interface exists."""
    if interface not in netifaces.interfaces():
        raise ValueError(f"Invalid network interface: {interface}")


def process_packet(packet: scapy.Packet) -> None:
    """Process a captured packet and extract relevant features."""
    try:
        if not packet.haslayer(scapy.IP):
            return
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        protocol = packet.proto
        packet_size = len(packet)
        timestamp = packet.time
        sport = None
        dport = None
        if packet.haslayer(scapy.TCP):
            sport = packet[scapy.TCP].sport
            dport = packet[scapy.TCP].dport
        elif packet.haslayer(scapy.UDP):
            sport = packet[scapy.UDP].sport
            dport = packet[scapy.UDP].dport
        packet_data.append([src_ip, dst_ip, protocol, packet_size, timestamp, sport, dport])
    except Exception as e:
        print(f"[!] Error processing packet: {e}")


def capture_traffic(interface: str, count: int, timeout: int) -> None:
    """Capture network packets on the specified interface."""
    try:
        print(f"[*] Capturing {count} packets on {interface}...")
        scapy.sniff(iface=interface, prn=process_packet, count=count, timeout=timeout)
    except PermissionError:
        print("[!] Error: Run as root (e.g., with sudo) to capture packets.")
        exit(1)
    except Exception as e:
        print(f"[!] Error capturing packets: {e}")
        exit(1)


def create_dataframe() -> pd.DataFrame:
    """Convert captured packet data to a DataFrame."""
    columns = ["src_ip", "dst_ip", "protocol", "packet_size", "timestamp", "sport", "dport"]
    return pd.DataFrame(list(packet_data), columns=columns)


def calculate_ip_entropy(df: pd.DataFrame, column: str) -> float:
    """Calculate Shannon entropy of values in a DataFrame column."""
    value_counts = df[column].value_counts()
    probabilities = value_counts / value_counts.sum()
    return entropy(probabilities, base=2)


def preprocess_data(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Preprocess packet data for anomaly detection."""
    df_processed = df.copy()
    df_processed["time_diff"] = df_processed["timestamp"].diff().fillna(0)
    df_processed["packet_size_log"] = np.log1p(df_processed["packet_size"])
    df_processed["packet_rate"] = 1 / df_processed["time_diff"].replace(0, np.inf).clip(
        upper=1000)  # Avoid division by zero
    df_processed["sport"] = pd.to_numeric(df_processed["sport"], errors='coerce').astype('Int64').fillna(0)
    df_processed["dport"] = pd.to_numeric(df_processed["dport"], errors='coerce').astype('Int64').fillna(0)

    # Calculate IP entropy for source IPs in the current window
    df_processed["ip_entropy"] = calculate_ip_entropy(df_processed, "src_ip")

    # Normalize numerical features
    features = ["protocol", "packet_size_log", "time_diff", "packet_rate", "sport", "dport", "ip_entropy"]
    for feature in features:
        if df_processed[feature].max() > df_processed[feature].min():
            df_processed[feature] = (df_processed[feature] - df_processed[feature].min()) / (
                    df_processed[feature].max() - df_processed[feature].min()
            )

    return df_processed[features], df_processed


def train_model(df: pd.DataFrame, contamination: float = 0.1, n_estimators: int = 100) -> IsolationForest:
    """Train an Isolation Forest model for anomaly detection."""
    model = IsolationForest(contamination=contamination, n_estimators=n_estimators, random_state=42)
    model.fit(df)
    return model


def detect_anomalies(model: IsolationForest, df_processed: pd.DataFrame, df_original: pd.DataFrame) -> pd.DataFrame:
    """Detect anomalies in the processed data."""
    df_original['anomaly'] = model.predict(df_processed)
    df_original['anomaly'] = df_original['anomaly'].map({1: 'Normal', -1: 'Anomaly'})
    return df_original


def log_results(df: pd.DataFrame, mode: str, interface: str) -> None:
    """Log anomaly detection results to a CSV file."""
    filename = f"network_anomalies_{mode}_{interface}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    try:
        log_df = df[
            [
                "src_ip",
                "dst_ip",
                "sport",
                "dport",
                "protocol",
                "packet_size",
                "time_diff",
                "packet_size_log",
                "packet_rate",
                "ip_entropy",
                "anomaly",
            ]
        ].copy()
        log_df["time_diff"] = log_df["time_diff"].round(4)
        log_df["packet_size_log"] = log_df["packet_size_log"].round(4)
        log_df["packet_rate"] = log_df["packet_rate"].round(4)
        log_df["ip_entropy"] = log_df["ip_entropy"].round(4)
        log_df.to_csv(filename, sep="\t", index=False, float_format="%.4f")
        print(f"[!] Anomaly log saved to {filename}")
    except Exception as e:
        print(f"[!] Error saving log file: {e}")


def visualize_results(df_analyzed: pd.DataFrame, save: bool = False, filename: Optional[str] = None) -> None:
    """Visualize anomaly detection results."""
    plt.figure(figsize=(10, 6))
    plt.scatter(
        df_analyzed["time_diff"],
        df_analyzed["packet_size_log"],
        c=df_analyzed["anomaly"].map({"Normal": "blue", "Anomaly": "red"}),
        alpha=0.6,
    )
    plt.xlabel("Time Difference (s)")
    plt.ylabel("Log Packet Size")
    plt.title("Network Traffic Anomalies")
    if save and filename:
        plt.savefig(filename)
        print(f"[!] Plot saved to {filename}")
    plt.show()


def batch_process(
        interface: str, count: int, contamination: float, n_estimators: int, visualize: bool
) -> None:
    """Run anomaly detection in batch mode."""
    packet_data.clear()
    capture_traffic(interface=interface, count=count, timeout=10)
    df = create_dataframe()

    if df.empty:
        print("[!] No packets captured")
        return

    df_processed, df_full = preprocess_data(df)
    model = train_model(df_processed, contamination=contamination, n_estimators=n_estimators)
    df_analyzed = detect_anomalies(model, df_processed, df_full)

    anomalies = df_analyzed[df_analyzed["anomaly"] == "Anomaly"]
    if not anomalies.empty:
        print("\n[!] Anomalies Detected:")
        print(
            tabulate.tabulate(
                anomalies[["src_ip", "dst_ip", "sport", "dport", "protocol", "packet_size", "anomaly"]],
                headers="keys",
                tablefmt="psql",
                showindex=False,
            )
        )
    else:
        print("\n[!] No anomalies detected.")

    log_results(df_analyzed, mode="batch", interface=interface)
    if visualize:
        visualize_results(df_analyzed, save=True, filename=f"anomaly_plot_batch_{interface}.png")


def real_time_detection(
        interface: str, window_size: int, contamination: float, n_estimators: int, retrain_interval: int = 1000
) -> None:
    """Run real-time anomaly detection with a sliding window."""
    model = None
    packet_counter = 0
    window_data = deque(maxlen=window_size)
    window_full_data = deque(maxlen=window_size)

    def process_and_analyze(packet: scapy.Packet) -> None:
        nonlocal model, packet_counter
        process_packet(packet)
        temp_df = create_dataframe()[-1:]
        if temp_df.empty:
            return

        df_processed, df_full = preprocess_data(temp_df)
        window_data.append(df_processed.iloc[0].to_dict())
        window_full_data.append(df_full.iloc[0].to_dict())
        packet_counter += 1

        if len(window_data) >= window_size:
            df_window = pd.DataFrame(list(window_data))
            df_full_window = pd.DataFrame(list(window_full_data))
            # Recalculate ip_entropy for the entire window
            df_window["ip_entropy"] = calculate_ip_entropy(df_full_window, "src_ip")
            if model is None or packet_counter % retrain_interval == 0:
                model = train_model(df_window, contamination=contamination, n_estimators=n_estimators)
            df_analyzed = detect_anomalies(model, df_processed, df_full)
            if df_analyzed["anomaly"].iloc[0] == "Anomaly":
                print(f"[!] Anomaly detected at {datetime.datetime.now()}:")
                print(
                    tabulate.tabulate(
                        df_analyzed[
                            ["src_ip", "dst_ip", "sport", "dport", "protocol", "packet_size", "anomaly"]
                        ],
                        headers="keys",
                        tablefmt="psql",
                        showindex=False,
                    )
                )

    print(f"[*] Starting real-time detection on {interface} (window size: {window_size})...")
    scapy.sniff(iface=interface, prn=process_and_analyze, store=0)


def parse_arguments() -> argparse.Namespace:
    """Parse and validate command-line arguments."""
    parser = argparse.ArgumentParser(description="Network Anomaly Detection Script")
    parser.add_argument(
        "--mode",
        type=str,
        choices=["batch", "real_time"],
        default="batch",
        help="Mode: 'batch' or 'real_time' (default: batch)",
    )
    parser.add_argument("--interface", type=str, default="lo", help="Network interface (default: lo)")
    parser.add_argument(
        "--count", type=int, default=100, help="Packets to capture in batch mode (default: 100)"
    )
    parser.add_argument(
        "--window-size", type=int, default=100, help="Window size for real-time detection (default: 100)"
    )
    parser.add_argument(
        "--contamination",
        type=float,
        default=0.1,
        help="Contamination factor for Isolation Forest (default: 0.1)",
    )
    parser.add_argument(
        "--n_estimators",
        type=int,
        default=100,
        help="Number of trees in Isolation Forest (default: 100)",
    )
    parser.add_argument("--visualize", action="store_true", help="Enable visualization in batch mode")
    return parser.parse_args()


def main() -> None:
    """Main function to run the anomaly detection script."""
    global packet_data  # Declare packet_data as global to modify it
    args = parse_arguments()
    try:
        validate_interface(args.interface)
        # Reinitialize packet_data with the appropriate maxlen
        packet_data = deque(maxlen=args.window_size if args.mode == "real_time" else DEFAULT_WINDOW_SIZE)
        if args.mode == "batch":
            batch_process(args.interface, args.count, args.contamination, args.n_estimators, args.visualize)
        else:
            real_time_detection(args.interface, args.window_size, args.contamination, args.n_estimators)
    except ValueError as e:
        print(f"[!] Error: {e}")
        exit(1)


if __name__ == "__main__":
    main()