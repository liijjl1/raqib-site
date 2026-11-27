import os
import time

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler
from sklearn.utils.class_weight import compute_sample_weight

# PythonAnywhere web apps cannot start threads, so the models use one core unless RAQIB_JOBS says otherwise.
N_JOBS = int(os.environ.get("RAQIB_JOBS", "1"))
MODEL_KEYS = ["if", "ae", "rf"]
MODEL_NAMES = {"if": "Isolation Forest", "ae": "Autoencoder", "rf": "Random Forest", "vote": "تصويت الأغلبية"}
POLICIES = {"majority": "أغلبية النماذج (2 من 3)", "any": "أي نموذج يكفي", "all": "كل النماذج معاً",
            "if": "Isolation Forest وحده", "ae": "Autoencoder وحده", "rf": "Random Forest وحده"}


class FeaturePipeline:
    def fit(self, frame):
        text_cols = list(frame.select_dtypes(exclude="number").columns)
        self.onehot_cols = [c for c in text_cols if frame[c].nunique() <= 20]
        self.dropped_cols = [c for c in text_cols if c not in self.onehot_cols]
        encoded = self._encode(frame)
        self.columns = list(encoded.columns)
        self.log_cols = [c for c in self.columns if encoded[c].min() >= 0]
        self.scaler = StandardScaler().fit(self._numbers(encoded))
        return self

    def _encode(self, frame):
        frame = frame.drop(columns=self.dropped_cols, errors="ignore")
        return pd.get_dummies(frame, columns=self.onehot_cols, dtype=float)

    def _numbers(self, encoded):
        X = encoded.reindex(columns=self.columns, fill_value=0.0).astype(float)
        X[self.log_cols] = np.log1p(X[self.log_cols].clip(lower=0))
        return X.to_numpy()

    def transform(self, frame):
        return self.scaler.transform(self._numbers(self._encode(frame)))


class IsolationForestDetector:
    def __init__(self, trees=200, seed=42):
        self.model = IsolationForest(n_estimators=trees, random_state=seed, n_jobs=N_JOBS)

    def fit(self, X_normal):
        self.model.fit(X_normal)
        return self

    def score(self, X):
        return -self.model.score_samples(X)


class AutoencoderDetector:
    def __init__(self, layers=(32, 16, 8, 16, 32), epochs=60, patience=5, max_rows=30000, seed=42):
        self.layers = layers
        self.epochs = epochs
        self.patience = patience
        self.max_rows = max_rows
        self.seed = seed

    def fit(self, X_normal):
        rng = np.random.default_rng(self.seed)
        if len(X_normal) > self.max_rows:
            X_normal = X_normal[rng.choice(len(X_normal), self.max_rows, replace=False)]
        order = rng.permutation(len(X_normal))
        n_val = max(1, len(X_normal) // 10)
        X_val, X_fit = X_normal[order[:n_val]], X_normal[order[n_val:]]
        self.model = MLPRegressor(hidden_layer_sizes=self.layers, activation="relu", solver="adam",
                                  learning_rate_init=0.001, batch_size=256, random_state=self.seed)
        self.history = {"train": [], "val": []}
        best_loss, best_weights, waited = np.inf, None, 0
        for epoch in range(self.epochs):
            batch = X_fit[rng.permutation(len(X_fit))]
            self.model.partial_fit(batch, batch)
            self.history["train"].append(float(self.score(X_fit).mean()))
            self.history["val"].append(float(self.score(X_val).mean()))
            if self.history["val"][-1] < best_loss:
                best_loss, waited = self.history["val"][-1], 0
                best_weights = ([w.copy() for w in self.model.coefs_], [b.copy() for b in self.model.intercepts_])
            else:
                waited += 1
                if waited >= self.patience:
                    break
        self.model.coefs_, self.model.intercepts_ = best_weights
        self.best_epoch = int(np.argmin(self.history["val"])) + 1
        return self

    def errors(self, X):
        return (X - self.model.predict(X)) ** 2

    def score(self, X):
        return self.errors(X).mean(axis=1)


class RandomForestDetector:
    def __init__(self, trees=200, seed=42):
        self.model = RandomForestClassifier(n_estimators=trees, n_jobs=N_JOBS, random_state=seed)

    def fit(self, X, labels, normal_label):
        self.model.fit(X, labels, sample_weight=compute_sample_weight("balanced", labels))
        self.normal_index = list(self.model.classes_).index(normal_label)
        return self

    def proba(self, X):
        return self.model.predict_proba(X)

    def score(self, X):
        return 1.0 - self.proba(X)[:, self.normal_index]

    def attack_guess(self, proba):
        attack_proba = proba.copy()
        attack_proba[:, self.normal_index] = 0.0
        best = attack_proba.argmax(axis=1)
        return [str(self.model.classes_[b]) if attack_proba[i, b] >= 0.15 else None for i, b in enumerate(best)]


class Calibrator:
    def __init__(self, normal_scores):
        self.normal_scores = np.asarray(normal_scores, dtype=float)
        self.set_sensitivity(99.0)

    def set_sensitivity(self, percentile):
        self.threshold = float(np.percentile(self.normal_scores, percentile))
        median = float(np.percentile(self.normal_scores, 50))
        ratio = np.log(max(median, 1e-12) / self.threshold)
        self.steepness = -np.log(9.0) / ratio if ratio < -1e-9 else 8.0

    def risk(self, scores):
        scores = np.maximum(np.asarray(scores, dtype=float), 1e-12)
        return 100.0 / (1.0 + (scores / self.threshold) ** (-self.steepness))


def combine(risks, policy="majority"):
    if policy == "any":
        return risks.max(axis=1)
    if policy == "all":
        return risks.min(axis=1)
    if policy in MODEL_KEYS:
        return risks[:, MODEL_KEYS.index(policy)]
    return np.median(risks, axis=1)


def timed(action):
    started = time.perf_counter()
    action()
    return time.perf_counter() - started


class AnomalySystem:
    def __init__(self, normal_label, trees=200, seed=42):
        self.normal_label = normal_label
        self.pipeline = FeaturePipeline()
        self.iforest = IsolationForestDetector(trees, seed)
        self.autoencoder = AutoencoderDetector(seed=seed)
        self.forest = RandomForestDetector(trees, seed)

    def fit(self, frame, labels):
        X = self.pipeline.fit(frame).transform(frame)
        X_normal = X[labels == self.normal_label]
        self.train_seconds = {
            "if": timed(lambda: self.iforest.fit(X_normal)),
            "ae": timed(lambda: self.autoencoder.fit(X_normal)),
            "rf": timed(lambda: self.forest.fit(X, labels, self.normal_label)),
        }
        self.iforest.model.set_params(n_jobs=1)
        self.forest.model.set_params(n_jobs=1)
        self.calibrators = {"if": Calibrator(self.iforest.score(X_normal)),
                            "ae": Calibrator(self.autoencoder.score(X_normal))}
        return self

    def set_sensitivity(self, percentile):
        for calibrator in self.calibrators.values():
            calibrator.set_sensitivity(percentile)

    def raw_score(self, key, X):
        if key == "if":
            return self.iforest.score(X)
        if key == "ae":
            return self.autoencoder.score(X)
        return self.forest.score(X)

    def risk(self, key, scores):
        if key == "rf":
            return 100.0 * np.asarray(scores)
        return self.calibrators[key].risk(scores)

    def assess(self, frame, policy="majority"):
        X = self.pipeline.transform(frame)
        errors = self.autoencoder.errors(X)
        proba = self.forest.proba(X)
        risks = np.column_stack([
            self.risk("if", self.iforest.score(X)),
            self.risk("ae", errors.mean(axis=1)),
            self.risk("rf", 1.0 - proba[:, self.forest.normal_index]),
        ])
        return {"risks": risks, "final": combine(risks, policy), "errors": errors,
                "guess": self.forest.attack_guess(proba)}
