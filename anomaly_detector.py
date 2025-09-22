# -*- coding: utf-8 -*-
"""
Isolation Forest anomaly detector with persisted scaler.
"""

from __future__ import annotations

import os

from typing import Dict, List, Optional
import hashlib
from datetime import datetime, timezone

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

MODEL_BUNDLE_VERSION = "1.0.0"


class AnomalyDetector:
    """Train, persist, and use an Isolation Forest with a StandardScaler."""

    def __init__(
        self,
        contamination: float = 0.05,
        n_estimators: int = 200,
        random_state: int = 42,
    ) -> None:
        self.model: Optional[IsolationForest] = None
        self.scaler: Optional[StandardScaler] = None
        self.feature_names: Optional[List[str]] = None

        self.meta: Dict[str, object] = {}

        self.contamination = float(contamination)
        self.n_estimators = int(n_estimators)
        self.random_state = int(random_state)

    def train(self, df_features: pd.DataFrame) -> None:
        if df_features is None or df_features.empty:
            raise ValueError("No features provided for training.")
        self.feature_names = list(df_features.columns)
        self.scaler = StandardScaler()
        X = self.scaler.fit_transform(df_features.values.astype(float))
        self.model = IsolationForest(
            contamination=self.contamination,
            n_estimators=self.n_estimators,
            random_state=self.random_state,
        ).fit(X)

    def _prepare_features(self, df_features: pd.DataFrame) -> np.ndarray:
        if self.model is None or self.scaler is None or self.feature_names is None:
            raise RuntimeError("Model not loaded/trained.")
        X = (
            df_features.reindex(columns=self.feature_names)
            .fillna(0.0)
            .values.astype(float)
        )
        return self.scaler.transform(X)

    def predict(self, df_features: pd.DataFrame):
        if self.model is None or self.scaler is None or self.feature_names is None:
            raise RuntimeError("Model not trained or loaded.")
        X = self._prepare_features(df_features)
        preds = self.model.predict(X)  # 1 (inlier) or -1 (outlier)
        return ["Anomaly" if p == -1 else "Normal" for p in preds]

    def decision_scores(self, df_features: pd.DataFrame):
        if self.model is None or self.scaler is None or self.feature_names is None:
            raise RuntimeError("Model not trained or loaded.")
        X = self._prepare_features(df_features)
        return self.model.decision_function(X)

    def save_model(self, path: str) -> None:
        os.makedirs(os.path.dirname(path), exist_ok=True)

        trained_at = datetime.now(timezone.utc).isoformat()

        payload = {
            "model": self.model,
            "scaler": self.scaler,
            "feature_names": self.feature_names,
            "meta": {
                "contamination": self.contamination,
                "n_estimators": self.n_estimators,
                "random_state": self.random_state,
                "version": MODEL_BUNDLE_VERSION,
                "trained_at": trained_at,
                "feature_checksum": self._feature_checksum(self.feature_names),
            },
        }
        joblib.dump(payload, path)

    def load_model(self, path: str) -> None:
        if not os.path.exists(path):
            raise FileNotFoundError(f"Model file does not exist: {path}")
        payload: Dict = joblib.load(path)
        self.model = payload.get("model", None)
        self.scaler = payload.get("scaler", None)
        self.feature_names = payload.get("feature_names", None)

        self.meta = dict(payload.get("meta", {}))

        if self.model is None or self.scaler is None or self.feature_names is None:
            raise RuntimeError("Loaded model bundle is incomplete.")

    @staticmethod
    def _feature_checksum(names: Optional[List[str]]) -> str:
        if not names:
            return ""
        data = ",".join(map(str, names)).encode("utf-8")
        return hashlib.sha256(data).hexdigest()

    def bundle_metadata(self) -> Dict[str, object]:
        """Return lightweight, human-readable bundle info."""
        return {
            "version": MODEL_BUNDLE_VERSION,
            "trained_at": self.meta.get("trained_at", ""),
            "feature_names": list(self.feature_names or []),
            "feature_count": len(self.feature_names or []),
            "feature_checksum": self._feature_checksum(self.feature_names),
            "params": {
                "contamination": self.contamination,
                "n_estimators": self.n_estimators,
                "random_state": self.random_state,
            },
        }
