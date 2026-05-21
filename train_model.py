import pandas as pd
import re
import joblib
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score

# ================= FEATURE EXTRACTION =================
def extract_features(url):
    parsed = urlparse(url)

    return [
        len(url),                                # URL length
        url.count('.'),                          # Dot count
        url.count('-'),                          # Hyphen count
        url.count('@'),                          # @ count
        1 if parsed.scheme == "https" else 0,    # HTTPS
        1 if re.search(r"\d", parsed.netloc) else 0,  # Numbers in domain
        len(parsed.netloc.split('.')),           # Subdomain count
        1 if parsed.netloc.replace('.', '').isdigit() else 0,  # IP used
        1 if "//" in url[8:] else 0              # Redirect trick
    ]

# ================= LOAD DATA =================
data = pd.read_csv("urls.csv")
data = data.dropna()

# Clean labels
data["label"] = data["label"].astype(str).str.strip().str.lower()

data["label"] = data["label"].map({
    "safe": 0,
    "legitimate": 0,
    "0": 0,
    "fake": 1,
    "phishing": 1,
    "1": 1,
    "-1": 1
})

data = data.dropna()

# ================= PREPARE DATA =================
X = data["url"].apply(extract_features).tolist()
y = data["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# ================= TRAIN MODEL =================
model = RandomForestClassifier(
    n_estimators=300,
    max_depth=15,
    random_state=42
)

model.fit(X_train, y_train)

# ================= CHECK ACCURACY =================
y_pred = model.predict(X_test)
print("Accuracy:", accuracy_score(y_test, y_pred))

# ================= SAVE MODEL =================
joblib.dump(model, "model.pkl")

print("Model trained and saved successfully!")