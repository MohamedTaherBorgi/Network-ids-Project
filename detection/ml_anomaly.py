import joblib
import os
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.neighbors import LocalOutlierFactor


class MLAnomalyDetector:
    def __init__(self, model_path="models/anomaly_model.pkl", threshold=0.5):
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Missing ML model: {model_path}")

        self.model = joblib.load(model_path)
        self.threshold = threshold

    def _vectorize(self, f):
        # MUST match training feature order
        return np.array([
            f.get("len", 0) or 0,
            f.get("sport", 0) or 0,
            f.get("dport", 0) or 0,
            int(f.get("syn", False)),
            int(f.get("ack", False)),
            int(f.get("fin", False)),
            int(f.get("rst", False)),
            int(f.get("psh", False)),
            int(f.get("urg", False)),
            f.get("payload_len", 0) or 0,
        ], dtype=float).reshape(1, -1)

    def evaluate(self, features):
        x = self._vectorize(features)

        # ------------------------------
        # Case 1: IsolationForest
        # ------------------------------
        if isinstance(self.model, IsolationForest):
            # isolation forest: negative scores = anomaly
            score = self.model.decision_function(x)[0]
            anomaly = score < -self.threshold
            return anomaly, score

        # ------------------------------
        # Case 2: OneClassSVM
        # ------------------------------
        if isinstance(self.model, OneClassSVM):
            score = self.model.decision_function(x)[0]
            # negative score = anomaly
            anomaly = score < -self.threshold
            return anomaly, score

        # ------------------------------
        # Case 3: LOF (LocalOutlierFactor)
        # ------------------------------
        if isinstance(self.model, LocalOutlierFactor):
            score = self.model._decision_function(x)[0]
            anomaly = score < -self.threshold
            return anomaly, score

        # ------------------------------
        # Case 4: Binary classifier (LogReg, XGBoost, NN)
        # ------------------------------
        if hasattr(self.model, "predict_proba"):
            proba = self.model.predict_proba(x)[0][1]  # anomaly probability
            anomaly = proba > self.threshold
            return anomaly, proba

        # ------------------------------
        # Case 5: Simple predict()
        # ------------------------------
        y = self.model.predict(x)[0]
        anomaly = (y == 1)
        return anomaly, y