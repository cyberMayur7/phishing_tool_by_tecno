import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.metrics import accuracy_score
import joblib
import os

def extract_url_features(url):
    length = len(url)
    has_https = 1 if url.lower().startswith("https") else 0
    has_at = 1 if "@" in url else 0
    num_dots = url.count('.')
    has_ip = 1 if any(part.isdigit() for part in url.split('/')[:3]) else 0
    return [length, has_https, has_at, num_dots, has_ip]

def train_url_model(csv_path="phishing_dataset.csv"):
    print("🔗 Loading URL dataset:", csv_path)
    df = pd.read_csv(csv_path)
    df = df.dropna(subset=['url','label'])
    X = df['url'].apply(extract_url_features).tolist()
    y = df['label'].astype(int).tolist()
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    print("✅ URL Model Accuracy:", round(accuracy_score(y_test, y_pred), 3))
    joblib.dump(model, "url_model.pkl")
    return model

def train_email_model(csv_path="email_dataset.csv"):
    print("📧 Loading Email dataset:", csv_path)
    df = pd.read_csv(csv_path)
    df = df.dropna(subset=['text','label'])
    vectorizer = CountVectorizer(stop_words='english', max_features=2000)
    X = vectorizer.fit_transform(df['text'].astype(str))
    y = df['label'].astype(int)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    print("✅ Email Model Accuracy:", round(accuracy_score(y_test, y_pred), 3))
    joblib.dump(model, "email_model.pkl")
    joblib.dump(vectorizer, "vectorizer.pkl")
    return model, vectorizer

def load_or_train_models():
    if os.path.exists("url_model.pkl"):
        url_model = joblib.load("url_model.pkl")
        print("Loaded saved url_model.pkl")
    else:
        url_model = train_url_model("phishing_dataset.csv")
    if os.path.exists("email_model.pkl") and os.path.exists("vectorizer.pkl"):
        email_model = joblib.load("email_model.pkl")
        vectorizer = joblib.load("vectorizer.pkl")
        print("Loaded saved email_model.pkl and vectorizer.pkl")
    else:
        email_model, vectorizer = train_email_model("email_dataset.csv")
    return url_model, email_model, vectorizer

def predict_url(url_model, url_input):
    feats = extract_url_features(url_input)
    pred = url_model.predict([feats])[0]
    proba = None
    try:
        proba = max(url_model.predict_proba([feats])[0])
    except Exception:
        pass
    return pred, proba

def predict_email(email_model, vectorizer, email_text):
    X = vectorizer.transform([email_text])
    pred = email_model.predict(X)[0]
    proba = None
    try:
        proba = max(email_model.predict_proba(X)[0])
    except Exception:
        pass
    return pred, proba

def main():
    print("=== Simple Phishing Detector (URL + Email) ===")
    url_model, email_model, vectorizer = load_or_train_models()
    while True:
        print("\nChoose option: 1) Check URL  2) Check Email  3) Exit")
        choice = input("Enter 1/2/3: ").strip()
        if choice == '1':
            url_input = input("Enter URL: ").strip()
            pred, proba = predict_url(url_model, url_input)
            if pred == 1:
                print("⚠️  Prediction: PHISHING URL")
            else:
                print("✅ Prediction: Legitimate URL")
            if proba is not None:
                print("Confidence:", round(proba*100,2), "%")
        elif choice == '2':
            print("Paste full email text (finish with an empty line):")
            lines = []
            while True:
                try:
                    line = input()
                except EOFError:
                    break
                if line.strip() == "":
                    break
                lines.append(line)
            email_text = "\n".join(lines)
            pred, proba = predict_email(email_model, vectorizer, email_text)
            if pred == 1:
                print("⚠️  Prediction: PHISHING EMAIL")
            else:
                print("✅ Prediction: Legitimate Email")
            if proba is not None:
                print("Confidence:", round(proba*100,2), "%")
        elif choice == '3':
            print("Exiting. Stay safe!")
            break
        else:
            print("Invalid choice. Try again.")

if __name__ == "__main__":
    main()
