import scapy.all as scapy
import netifaces
from packet_processor import PacketProcessor
from anomaly_detector import AnomalyDetector
import pandas as pd

class NetworkMonitor:
    # The core IDS engine that monitors network traffice
    def __init__(self, config):
        self.config = config
        self.processor = PacketProcessor(window_size=config.getint('DEFAULT', 'DefaultWindowSize'))
        self.detector = AnomalyDetector(
            contamination=config.get('IsolationForest', 'Contamination'),
            n_estimators=config.get('IsolationForest', 'NEstimators'),
            random_state=config.get('IsolationForest', 'RandomState')
        )

    def _validate_interface(self, interface: str):
        # Validate if the network interface exist
        if interface not in netifaces.interfaces():
            raise ValueError(f'Invalid network interfaces: {interface}')
        
    def capture_and_train(self, interface: str, packet_count: int, model_path: str):
        # Capture a batch of packets to train and save a new model
        self._validate_interface(interface)
        print(f'[*] Capturing {packet_count} packets on {interface} for training...')
        scapy.sniff(iface=interface, prn=self.processor.process_packet, count=packet_count)

        df = self.processor.get_dataframe()
        if df.empty:
            print(f'[!] No packets captured for training. Exiting')
            return
        
        df_features, _ = self.processor.engineer_features(df)
        self.detector.train(df_features)
        self.detector.save_model(model_path)

    def start_monitoring(self, interface: str, model_path: str):
        # Starts real-time monitoring using a pre-trained model
        self._validate_interface(interface)
        self.detector.load_model(model_path)

        print(f'[*] Starting real-time detection on {interface}...')
        scapy.sniff(iface=interface, prn=self._analyze_packet, store=0)

    def _analyze_packet(self, packet: scapy.Packet):
        # The callback function for real-time packet analysis
        self.processor.process_packet(packet)

        # We analyze the most recent packet by creating a temporary single-row DataFrame
        if not self.processor.packet_data:
            return
        
        recent_packet_df = pd.DataFrame([self.processor.packet_data[-1]])
        df_features, _ = self.processor.engineer_features(recent_packet_df)

        if not df_features.empty:
            prediction = self.detector.predict(df_features)
            if prediction[0] == 'Anomaly':
                # This is where you would log to your database in the future
                print('\n--- ANOMALY DETECTED ---')
                print(recent_packet_df[['timestamp', 'src_ip', 'dst_ip', 'protocol', 'packet_size']].to_string(index=False))
                print('------------------------\n')