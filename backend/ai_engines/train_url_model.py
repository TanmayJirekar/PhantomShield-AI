import kagglehub
import pandas as pd
import os
import joblib
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import accuracy_score, classification_report

print("Downloading/Locating dataset...")
path = kagglehub.dataset_download("shashwatwork/web-page-phishing-detection-dataset")

csv_file = None
for file in os.listdir(path):
    if file.endswith(".csv"):
        csv_file = os.path.join(path, file)
        break

if not csv_file:
    raise FileNotFoundError("Dataset CSV not found in downloaded files.")

print(f"Loading dataset from {csv_file}...")
df = pd.read_csv(csv_file)

selected_features = [
    'length_url', 'nb_dots', 'nb_hyphens', 'nb_at', 'nb_qm', 'nb_and', 'nb_or',
    'nb_eq', 'nb_underscore', 'nb_tilde', 'nb_percent', 'nb_slash', 'nb_star',
    'nb_colon', 'nb_comma', 'nb_semicolumn', 'nb_dollar', 'nb_space', 'nb_www',
    'nb_com', 'nb_dslash', 'http_in_path', 'https_token', 'ratio_digits_url', 'punycode',
]

print(f"Selected {len(selected_features)} features for training.")

X = df[selected_features]
y = df['status'].map({'phishing': 1, 'legitimate': 0})

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print("Training ensemble classifier (RandomForest + GradientBoosting)...")
rf = RandomForestClassifier(
    n_estimators=200,
    max_depth=20,
    min_samples_split=5,
    class_weight='balanced',
    random_state=42,
    n_jobs=-1,
)
gb = GradientBoostingClassifier(n_estimators=100, max_depth=6, random_state=42)
model = VotingClassifier(
    estimators=[('rf', rf), ('gb', gb)],
    voting='soft',
)

model.fit(X_train, y_train)

cv_scores = cross_val_score(model, X_train, y_train, cv=5, scoring='accuracy')
print(f"Cross-validation accuracy: {cv_scores.mean() * 100:.2f}% (+/- {cv_scores.std() * 200:.2f}%)")

y_pred = model.predict(X_test)
acc = accuracy_score(y_test, y_pred)
print(f"Test set accuracy: {acc * 100:.2f}%")
print("\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=['Legitimate (0)', 'Phishing (1)']))

model_path = os.path.join(os.path.dirname(__file__), 'url_phishing_model.pkl')
joblib.dump(model, model_path)
print(f"Model saved successfully to {model_path}")
