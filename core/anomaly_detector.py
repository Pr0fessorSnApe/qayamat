"""QAYAMAT — Anomaly Detector
Uses Isolation Forest to detect anomalous HTTP responses that may indicate vulnerabilities.
"""

import numpy as np
from typing import List, Dict, Any


class AnomalyDetector:
    def __init__(self, contamination: float = 0.05):
        self.contamination = contamination
        self.fitted = False
        self._model = None

    def _to_features(self, d: Dict[str, Any]) -> List[float]:
        return [
            d.get("status", 200) / 100.0,
            min(d.get("size", 1000), 1_000_000) / 1000.0,
            min(d.get("time", 0.5), 60.0) * 10.0,
            float(d.get("redirects", 0)),
        ]

    def train(self, baseline_data: List[Dict[str, Any]]) -> None:
        """Fit the model on a list of normal response dicts."""
        if len(baseline_data) < 10:
            return  # Not enough data to fit reliably

        try:
            from sklearn.ensemble import IsolationForest

            X = np.array([self._to_features(d) for d in baseline_data])
            self._model = IsolationForest(
                contamination=self.contamination,
                random_state=42,
                n_estimators=100,
            )
            self._model.fit(X)
            self.fitted = True
        except ImportError:
            pass  # scikit-learn not available

    def is_anomaly(self, response_data: Dict[str, Any]) -> bool:
        """Return True if the response looks anomalous compared to baseline."""
        if not self.fitted or self._model is None:
            return False
        x = np.array([self._to_features(response_data)])
        return self._model.predict(x)[0] == -1

    def anomaly_score(self, response_data: Dict[str, Any]) -> float:
        """Return raw anomaly score (more negative = more anomalous). 0.0 if not fitted."""
        if not self.fitted or self._model is None:
            return 0.0
        x = np.array([self._to_features(response_data)])
        return float(self._model.score_samples(x)[0])
