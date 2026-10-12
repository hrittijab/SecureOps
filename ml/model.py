
import numpy as np

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


class AuthenticationAnomalyDetector:
    """
    Isolation Forest anomaly detector for authentication windows.

    Training data should contain normal authentication behavior.
    """

    def __init__(self, contamination=0.05, random_state=42):
        self.scaler = StandardScaler()

        self.model = IsolationForest(
            n_estimators=200,
            contamination=contamination,
            random_state=random_state,
            n_jobs=-1,
        )

        self.fitted = False

    def fit(self, training_data):
        X = np.asarray(training_data, dtype=float)

        if X.ndim != 2 or X.shape[0] < 2:
            raise ValueError(
                "Training data must contain at least two feature rows"
            )

        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)

        self.fitted = True
        return self

    def predict(self, feature_data):
        if not self.fitted:
            raise RuntimeError("Model must be trained before prediction")

        X = np.asarray(feature_data, dtype=float)

        if X.ndim != 2:
            raise ValueError("Feature data must be a 2D matrix")

        if X.shape[1] != self.model.n_features_in_:
            raise ValueError("Feature count does not match training data")

        if X.shape[0] == 0:
            return []

        X_scaled = self.scaler.transform(X)

        # Isolation Forest returns -1 for anomalies and 1 for normal.
        predictions = self.model.predict(X_scaled)

        return [
            prediction == -1
            for prediction in predictions
        ]

    def anomaly_scores(self, feature_data):
        if not self.fitted:
            raise RuntimeError("Model must be trained before scoring")

        X = np.asarray(feature_data, dtype=float)

        if X.ndim != 2:
            raise ValueError("Feature data must be a 2D matrix")

        if X.shape[1] != self.model.n_features_in_:
            raise ValueError("Feature count does not match training data")

        if X.shape[0] == 0:
            return []

        X_scaled = self.scaler.transform(X)

        # Higher score means more anomalous.
        scores = -self.model.decision_function(X_scaled)

        return scores.tolist()
