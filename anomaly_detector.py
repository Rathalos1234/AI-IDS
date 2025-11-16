# -*- coding: utf-8 -*-
"""
Isolation Forest anomaly detector with persisted scaler.
"""

from __future__ import annotations

import os
import contextlib
import hashlib
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple
import joblib
from joblib.numpy_pickle import NumpyUnpickler
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

DEFAULT_MODEL_DIR = Path(os.environ.get("MODEL_DIR", "models")).resolve()

MODEL_BUNDLE_VERSION = "1.0.0"


class SecurityError(RuntimeError):
    """Raised when a model bundle fails security validation."""


_BANNED_GLOBALS: Tuple[Tuple[str, str], ...] = (
    ("os", "system"),
    ("posix", "system"),
    ("subprocess", "Popen"),
    ("subprocess", "call"),
    ("subprocess", "check_call"),
    ("builtins", "eval"),
    ("builtins", "exec"),
    ("builtins", "__import__"),
)


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

    def _ensure_dataframe(
        self,
        data,
        *,
        feature_names: Optional[Iterable[str]] = None,
    ) -> pd.DataFrame:
        if isinstance(data, pd.DataFrame):
            return data.copy()
        if isinstance(data, np.ndarray):
            if data.ndim != 2:
                raise ValueError("Feature array must be 2-dimensional")
            cols = list(feature_names or [f"f{i}" for i in range(data.shape[1])])
            if len(cols) != data.shape[1]:
                raise ValueError("Feature name count does not match data width")
            return pd.DataFrame(data, columns=cols)
        if isinstance(data, list) and data:
            if isinstance(data[0], dict):
                return pd.DataFrame(data)
        if data is None:
            raise ValueError("No features provided")
        raise TypeError("Unsupported feature container")

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
            n_jobs=-1,
        ).fit(X)

    def fit(self, features) -> "AnomalyDetector":
        df = self._ensure_dataframe(features)
        self.train(df)
        return self

    def _prepare_features(self, df_features: pd.DataFrame) -> np.ndarray:
        if self.model is None or self.scaler is None or self.feature_names is None:
            raise RuntimeError("Model not loaded/trained.")
        X = (
            df_features.reindex(columns=self.feature_names)
            .fillna(0.0)
            .values.astype(float)
        )
        return self.scaler.transform(X)

    def predict(self, df_features):
        if self.model is None or self.scaler is None or self.feature_names is None:
            raise RuntimeError("Model not trained or loaded.")
        df = self._ensure_dataframe(df_features, feature_names=self.feature_names)
        X = self._prepare_features(df)
        preds = self.model.predict(X)  # 1 (inlier) or -1 (outlier)
        return ["Anomaly" if p == -1 else "Normal" for p in preds]

    def decision_scores(self, df_features):
        if self.model is None or self.scaler is None or self.feature_names is None:
            raise RuntimeError("Model not trained or loaded.")
        df = self._ensure_dataframe(df_features, feature_names=self.feature_names)
        X = self._prepare_features(df)
        return self.model.decision_function(X)

    def save(self, path: str) -> str:
        resolved = self._resolve_model_path(path, must_exist=False)
        self.save_model(str(resolved))
        return str(resolved)

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
        directory = os.path.dirname(path) or "."
        fd, tmp_path = tempfile.mkstemp(prefix="model-", suffix=".tmp", dir=directory)
        os.close(fd)
        try:
            joblib.dump(payload, tmp_path)
            os.replace(tmp_path, path)
        except Exception:
            with contextlib.suppress(FileNotFoundError):
                os.remove(tmp_path)
            raise

    def load(self, path: str) -> "AnomalyDetector":
        resolved = self._resolve_model_path(path, must_exist=True)
        self.load_model(str(resolved))
        return self

    def load_model(self, path: str) -> None:
        if not os.path.exists(path):
            raise FileNotFoundError(f"Model file does not exist: {path}")

        payload: Dict = self._load_secure_payload(path)
        self.model = payload.get("model", None)
        self.scaler = payload.get("scaler", None)
        self.feature_names = payload.get("feature_names", None)

        self.meta = dict(payload.get("meta", {}))

        if self.model is None or self.scaler is None or self.feature_names is None:
            raise RuntimeError("Loaded model bundle is incomplete.")

    @staticmethod
    def _resolve_model_path(path: str, *, must_exist: bool) -> Path:
        candidate = Path(path)
        if candidate.is_absolute():
            resolved = candidate.resolve()
        else:
            resolved = (DEFAULT_MODEL_DIR / candidate).resolve()
            try:
                resolved.relative_to(DEFAULT_MODEL_DIR)
            except ValueError as exc:
                raise ValueError("Model path escapes allowed directory") from exc
        if must_exist and not resolved.exists():
            raise FileNotFoundError(f"Model file does not exist: {resolved}")
        resolved.parent.mkdir(parents=True, exist_ok=True)
        return resolved

    @staticmethod
    def _feature_checksum(names: Optional[List[str]]) -> str:
        if not names:
            return ""
        data = ",".join(map(str, names)).encode("utf-8")
        return hashlib.sha256(data).hexdigest()

    def _load_secure_payload(self, path: str) -> Dict:
        class _SecureUnpickler(NumpyUnpickler):
            def find_class(self, module: str, name: str):
                candidate = (module, name)
                if candidate in _BANNED_GLOBALS:
                    raise SecurityError(
                        f"Blocked unsafe global reference {candidate[0]}.{candidate[1]}"
                    )
                return super().find_class(module, name)

        try:
            with open(path, "rb") as fh:
                unpickler = _SecureUnpickler(path, fh, ensure_native_byte_order=True)
                payload = unpickler.load()
        except SecurityError:
            raise
        except Exception as exc:
            raise RuntimeError("Failed to load model bundle") from exc

        if not isinstance(payload, dict):
            raise RuntimeError("Model bundle has unexpected structure")
        return payload

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
