"""DBSCAN clustering of attack feature vectors."""
import numpy as np
from sklearn.cluster import DBSCAN
from collections import defaultdict

attack_features: list = []
attack_payloads: list = []


def add_attack_sample(features: list, payload: str) -> None:
    attack_features.append(features)
    attack_payloads.append(payload)
    if len(attack_features) > 500:   # cap memory
        attack_features.pop(0)
        attack_payloads.pop(0)


def run_clustering() -> dict:
    if len(attack_features) < 4:
        return {"message": "Need at least 4 attack samples for clustering."}
    try:
        X = np.array(attack_features, dtype=float)
        labels = DBSCAN(eps=0.7, min_samples=2).fit(X).labels_
        clusters: dict = defaultdict(list)
        for label, payload in zip(labels, attack_payloads):
            clusters[str(label)].append(payload[:120])
        return dict(clusters)
    except Exception as e:
        return {"error": str(e)}
