import streamlit as st
import joblib
from urllib.parse import urlparse

model = joblib.load("url_model.pkl")
vec = joblib.load("vectorizer.pkl")

st.title("Phishing Detector Demo")
url = st.text_input("Enter URL:")
if st.button("Check URL"):
    parsed = urlparse(url)
    if not parsed.scheme:
        url = "http://" + url
    X = [url]
    Xv = vec.transform(X)
    pred = model.predict(Xv)[0]
    prob = model.predict_proba(Xv).max()
    st.success(f"Prediction: {pred} — Confidence: {prob:.2f}")
