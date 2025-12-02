import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest


class AnomalyTrainer:
    def __init__(self, input_csv="data/deep_packets.csv", model_path="models/anomaly_model.pkl"):
        self.input_csv = input_csv
        self.model_path = model_path

    def load_data(self):
        df = pd.read_csv(self.input_csv)

        # Strictly select the features used in vectorization order
        features = [
            "len",
            "sport",
            "dport",
            "syn",
            "ack",
            "fin",
            "rst",
            "psh",
            "urg",
            "payload_len",
        ]

        df = df[features].fillna(0)
        return df

    def train(self):
        df = self.load_data()

        model = IsolationForest(
            n_estimators=200,
            contamination=0.05,
            random_state=42,
        )

        model.fit(df)

        joblib.dump(model, self.model_path)

        print(f"Model trained and saved to {self.model_path}")
        return model


if __name__ == "__main__":
    trainer = AnomalyTrainer()
    trainer.train()