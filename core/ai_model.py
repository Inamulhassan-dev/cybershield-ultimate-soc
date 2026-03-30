"""
CyberShield Ultimate - AI Model
Loads the trained Random Forest model and makes traffic predictions.
"""

import os
import joblib
import numpy as np

ATTACK_LABELS = ['Normal', 'DDoS', 'SQL Injection', 'Port Scan', 'Brute Force']
FEATURE_NAMES = [
    'duration', 'protocol_type', 'src_bytes', 'dst_bytes', 'flag',
    'count', 'srv_count', 'serror_rate', 'rerror_rate', 'same_srv_rate',
    'diff_srv_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
    'dst_host_serror_rate', 'dst_host_rerror_rate'
]

MODEL_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'cyber_model.pkl')

_model = None


def load_model():
    """Load the trained model from disk."""
    global _model
    if _model is None:
        if os.path.exists(MODEL_PATH):
            _model = joblib.load(MODEL_PATH)
        else:
            raise FileNotFoundError(
                f"Model not found at {MODEL_PATH}. Run train_model.py first."
            )
    return _model


def predict_traffic(features):
    """
    Predict traffic classification.

    Args:
        features: list of 17 numeric feature values

    Returns:
        dict with prediction label, confidence, and feature importance
    """
    model = load_model()
    features_array = np.array(features).reshape(1, -1)

    prediction = model.predict(features_array)[0]
    probabilities = model.predict_proba(features_array)[0]

    label = ATTACK_LABELS[prediction]
    confidence = float(probabilities[prediction]) * 100

    # Get top contributing features
    importances = model.feature_importances_
    top_indices = np.argsort(importances)[-5:][::-1]
    top_features = [
        {'name': FEATURE_NAMES[i], 'importance': round(float(importances[i]) * 100, 2)}
        for i in top_indices
    ]

    return {
        'label': label,
        'confidence': round(confidence, 2),
        'is_threat': label != 'Normal',
        'probabilities': {
            ATTACK_LABELS[i]: round(float(p) * 100, 2)
            for i, p in enumerate(probabilities)
        },
        'top_features': top_features,
    }


def predict_batch(samples):
    """Predict multiple traffic samples at once."""
    results = []
    for sample in samples:
        features = sample.get('features', sample)
        result = predict_traffic(features)
        if isinstance(sample, dict):
            result['src_ip'] = sample.get('src_ip', 'N/A')
            result['dst_ip'] = sample.get('dst_ip', 'N/A')
            result['protocol'] = sample.get('protocol', 'N/A')
            result['service'] = sample.get('service', 'N/A')
            result['timestamp'] = sample.get('timestamp', 'N/A')
        results.append(result)
    return results
