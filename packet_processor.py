import scapy.all as scapy
import pandas as pd
import numpy as np
from scipy.stats import entropy
from collections import deque

class PacketProcessor:
    # Process raw Scapy packets and engineers features for the ML model
    def __init__(self, window_size=100):
        self.packet_data = deque(maxlen=window_size)
        self.features = ['protocol', 'packet_size_log', 'time_diff', 'packet_rate', 'sport', 'dport', 'ip_entropy']

    def process_packet(self, packet: scapy.Packet):
        # Extract key info from a single Scapy packet
        try:
            if not packet.haslayer(scapy.IP):
                return
            
            record = {
                'timestamp': packet.time,
                'src_ip': packet[scapy.IP].src,
                'dest_ip': packet[scapy.IP].dst,
                'protocol': packet.proto,
                'packet_size': len(packet),
                'sport': packet.sport if packet.haslayer(scapy.TCP) or packet.haslayer(scapy.UDP) else 0,
                'dport': packet.dport if packet.haslayer(scapy.TCP) or packet.haslayer(scapy.UDP) else 0
            }
            self.packet_data.append(record)
        except Exception as e:
            print(f'[!] Error processing packet: {e}')

    def get_dataframe(self) -> pd.DataFrame:
        # Convert the deque of packet data into a pandas Dataframe
        return pd.DataFrame(list(self.packet_data))
    
    def _calculate_ip_entropy(self, df: pd.DataFrame, column: str) -> float:
        # Calculate the Shannon entropy for an IP column
        if df[column].empty:
            return 0.0
        value_counts = df[column].value_counts()
        probabilities = value_counts / value_counts.sum()
        return entropy(probabilities, base=2)
    
    def engineer_features(self, df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
        # Engineer features from the raw packet DataFrame
        if df.empty:
            return pd.DataFrame(), df
        
        df_processed = df.copy()
        df_processed['time_diff'] = df_processed['timestamp'].diff().fillna(0)
        df_processed['packet_size_log'] = np.log1p(df_processed['packet_size'])
        # Avoid division by zero for packet_rate
        df_processed['packet_rate'] = 1 / df_processed['time_diff'].replace(0,np.inf)
        df_processed['ip_entropy'] = self.calculate_ip_entropy(df_processed, 'src_ip')

        # Normalize features
        for feature in self.features:
            if feature in df_processed.columns and df_processed[feature].std() > 0:
                mean = df_processed[feature].mean()
                std = df_processed[feature].std()
                df_processed[feature] = (df_processed[feature] - mean) / std

        return df_processed[self.features].fillna(0), df_processed