"""
CyberShield Ultimate - Real AI Model Training
Trains on the REAL NSL-KDD dataset (network intrusion detection).
Downloads the dataset automatically if not present.
"""

import os
import sys
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.preprocessing import LabelEncoder

MODEL_PATH = os.path.join(os.path.dirname(__file__), 'cyber_model.pkl')
DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')

# NSL-KDD column names (41 features + 2 labels)
KDD_COLUMNS = [
    'duration', 'protocol_type', 'service', 'flag',
    'src_bytes', 'dst_bytes', 'land', 'wrong_fragment', 'urgent',
    'hot', 'num_failed_logins', 'logged_in', 'num_compromised',
    'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
    'num_shells', 'num_access_files', 'num_outbound_cmds',
    'is_host_login', 'is_guest_login',
    'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
    'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
    'srv_diff_host_rate',
    'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
    'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
    'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
    'dst_host_srv_rerror_rate',
    'attack_type', 'difficulty_level'
]

# Map NSL-KDD attack types to our 5 classes
ATTACK_MAPPING = {
    # Normal
    'normal': 'Normal',
    # DoS attacks -> DDoS
    'back': 'DDoS', 'land': 'DDoS', 'neptune': 'DDoS', 'pod': 'DDoS',
    'smurf': 'DDoS', 'teardrop': 'DDoS', 'apache2': 'DDoS',
    'udpstorm': 'DDoS', 'processtable': 'DDoS', 'mailbomb': 'DDoS',
    # Probe attacks -> Port Scan
    'satan': 'Port Scan', 'ipsweep': 'Port Scan', 'nmap': 'Port Scan',
    'portsweep': 'Port Scan', 'mscan': 'Port Scan', 'saint': 'Port Scan',
    # R2L attacks -> Brute Force
    'guess_passwd': 'Brute Force', 'ftp_write': 'Brute Force',
    'imap': 'Brute Force', 'phf': 'Brute Force', 'multihop': 'Brute Force',
    'warezmaster': 'Brute Force', 'warezclient': 'Brute Force',
    'spy': 'Brute Force', 'xlock': 'Brute Force', 'xsnoop': 'Brute Force',
    'snmpguess': 'Brute Force', 'snmpgetattack': 'Brute Force',
    'httptunnel': 'Brute Force', 'sendmail': 'Brute Force',
    'named': 'Brute Force', 'worm': 'Brute Force',
    # U2R attacks -> SQL Injection (closest analogy for privilege escalation)
    'buffer_overflow': 'SQL Injection', 'loadmodule': 'SQL Injection',
    'rootkit': 'SQL Injection', 'perl': 'SQL Injection',
    'sqlattack': 'SQL Injection', 'xterm': 'SQL Injection',
    'ps': 'SQL Injection', 'httptunnel': 'SQL Injection',
}

ATTACK_LABELS = ['Normal', 'DDoS', 'SQL Injection', 'Port Scan', 'Brute Force']

# The 17 features our model uses (subset of the 41 NSL-KDD features)
MODEL_FEATURES = [
    'duration', 'protocol_type', 'src_bytes', 'dst_bytes', 'flag',
    'count', 'srv_count', 'serror_rate', 'rerror_rate', 'same_srv_rate',
    'diff_srv_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
    'dst_host_serror_rate', 'dst_host_rerror_rate'
]


def download_dataset():
    """Download the NSL-KDD dataset if not present."""
    os.makedirs(DATA_DIR, exist_ok=True)
    train_file = os.path.join(DATA_DIR, 'KDDTrain+.txt')
    test_file = os.path.join(DATA_DIR, 'KDDTest+.txt')

    if os.path.exists(train_file) and os.path.exists(test_file):
        print("[✓] NSL-KDD dataset already downloaded")
        return train_file, test_file

    print("[*] Downloading NSL-KDD dataset...")
    import urllib.request

    base_url = 'https://raw.githubusercontent.com/defcom17/NSL_KDD/master/'
    urls = {
        'KDDTrain+.txt': base_url + 'KDDTrain%2B.txt',
        'KDDTest+.txt': base_url + 'KDDTest%2B.txt',
    }

    for filename, url in urls.items():
        filepath = os.path.join(DATA_DIR, filename)
        print(f"    Downloading {filename}...")
        try:
            urllib.request.urlretrieve(url, filepath)
            file_size = os.path.getsize(filepath) / (1024 * 1024)
            print(f"    ✓ {filename} ({file_size:.1f} MB)")
        except Exception as e:
            print(f"    ✗ Failed to download {filename}: {e}")
            print(f"\n    Please manually download from:")
            print(f"    {url}")
            print(f"    Save to: {filepath}")
            sys.exit(1)

    return train_file, test_file


def load_and_prepare_data(train_path, test_path):
    """Load NSL-KDD data and prepare for training."""
    print("\n[*] Loading dataset...")

    # Load data
    df_train = pd.read_csv(train_path, names=KDD_COLUMNS, header=None)
    df_test = pd.read_csv(test_path, names=KDD_COLUMNS, header=None)

    print(f"    Training samples: {len(df_train):,}")
    print(f"    Testing samples:  {len(df_test):,}")

    # Combine for consistent encoding
    df = pd.concat([df_train, df_test], ignore_index=True)

    # Encode categorical features
    le_protocol = LabelEncoder()
    le_flag = LabelEncoder()
    df['protocol_type'] = le_protocol.fit_transform(df['protocol_type'])
    df['flag'] = le_flag.fit_transform(df['flag'])

    # Map attack types to our 5 classes
    df['label'] = df['attack_type'].str.strip().str.lower().map(ATTACK_MAPPING)
    # Any unmapped attack types default to 'SQL Injection' (exploit category)
    df['label'] = df['label'].fillna('SQL Injection')

    # Encode labels to integers
    le_label = LabelEncoder()
    le_label.fit(ATTACK_LABELS)
    df['label_encoded'] = le_label.transform(df['label'])

    # Extract our 17 features
    X = df[MODEL_FEATURES].values.astype(np.float64)
    y = df['label_encoded'].values

    # Split back into train/test using original sizes
    n_train = len(df_train)
    X_train, X_test = X[:n_train], X[n_train:]
    y_train, y_test = y[:n_train], y[n_train:]

    print(f"\n    Feature matrix shape: {X_train.shape}")
    print(f"    Classes: {ATTACK_LABELS}")

    # Show class distribution
    for i, label in enumerate(ATTACK_LABELS):
        count = np.sum(y_train == i)
        pct = count / len(y_train) * 100
        print(f"    - {label}: {count:,} samples ({pct:.1f}%)")

    return X_train, X_test, y_train, y_test


def train():
    print("=" * 60)
    print("  CyberShield Ultimate - Real AI Model Training")
    print("  Using NSL-KDD Network Intrusion Detection Dataset")
    print("=" * 60)

    # Download dataset
    train_path, test_path = download_dataset()

    # Load and prepare
    X_train, X_test, y_train, y_test = load_and_prepare_data(train_path, test_path)

    # Train model
    print("\n[*] Training Random Forest Classifier (200 trees)...")
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=30,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1,
        class_weight='balanced',  # Handle class imbalance
    )
    model.fit(X_train, y_train)

    # Evaluate on training set
    train_acc = model.score(X_train, y_train)
    print(f"    Training accuracy: {train_acc * 100:.2f}%")

    # Evaluate on test set
    print("\n[*] Evaluating on test set...")
    test_acc = model.score(X_test, y_test)
    print(f"    Test accuracy: {test_acc * 100:.2f}%")

    y_pred = model.predict(X_test)
    print("\n" + classification_report(
        y_test, y_pred,
        target_names=ATTACK_LABELS,
        digits=3
    ))

    # Feature importance
    print("[*] Top 10 most important features:")
    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1]
    for rank, idx in enumerate(indices[:10], 1):
        print(f"    {rank}. {MODEL_FEATURES[idx]}: {importances[idx] * 100:.2f}%")

    # Save model
    print(f"\n[*] Saving model to {MODEL_PATH}...")
    joblib.dump(model, MODEL_PATH)
    model_size = os.path.getsize(MODEL_PATH) / (1024 * 1024)
    print(f"    Model size: {model_size:.1f} MB")

    print(f"\n[✓] Training complete!")
    print(f"    Model trained on REAL NSL-KDD data with {test_acc * 100:.1f}% accuracy")
    print("=" * 60)


if __name__ == '__main__':
    train()
