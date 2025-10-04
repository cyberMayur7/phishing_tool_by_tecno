# train.py
import argparse
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from joblib import dump

def train(csv_path="data/phishing_dataset.csv", out="models/url_model.pkl"):
    df = pd.read_csv(csv_path)
    # expect df has columns: 'text' and 'label' (1=phish, 0=legit)
    X = df["text"].astype(str)
    y = df["label"].astype(int)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    pipe = Pipeline([
        ("vect", TfidfVectorizer(ngram_range=(1,2), max_features=5000)),
        ("clf", RandomForestClassifier(n_estimators=100, random_state=42))
    ])
    pipe.fit(X_train, y_train)
    print("Train score:", pipe.score(X_train, y_train))
    print("Test score:", pipe.score(X_test, y_test))
    dump(pipe, out)
    print("Saved model ->", out)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", default="data/phishing_dataset.csv")
    parser.add_argument("--out", default="models/url_model.pkl")
    args = parser.parse_args()
    train(args.csv, args.out)
