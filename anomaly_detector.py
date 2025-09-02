import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib
import os

class AnomalyDetector:
    # Handles the Isolation Forest model for anomaly detection
    def __init__(self, contamination=0.1, n_estimators=100, random_state=42):
        self.model = IsolationForest(contamination=float(contamination),
                                     n_estimators=int(n_estimators),
                                     random_state=int(random_state))
        
    def train(self, df_features: pd.DataFrame):
        # Train the Isolation Forest model on the provided feature DataFrame
        print('[*] Train model...')
        self.model.fit(df_features)
        print('[*] Model training complete')

    def predict(self, df_features: pd.DataFrame) -> list:
        # Predict anomalies on new data
        predictions = self.model.predict(df_features)
        # Map predictions to 'Normal' (1) and 'Anomaly' (-1)
        return ['Normal' if p == 1 else 'Anomaly' for p in predictions]
    
    def save_model(self, path: str):
        # Save the trained model to a file
        print(f'[*] Saving model to {path}...')
        os.makedirs(os.path.dirname(path), exist_ok=True)
        joblib.dump(self.model, path)
        print('[+] Model saved successfully')

    def load_model(self, path: str):
        # Loads a pre-trained model from a file
        if os.path .exists(path):
            print(f'[*] Loading a pre-trained model from {path}...')
            self.model = joblib.load(path)
            print(f'[+] Model loaded successfully')
        else:
            raise FileNotFoundError(f'Model file not found at {path}')