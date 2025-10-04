# src/model.py
from joblib import dump, load
from typing import Tuple

def save_model(obj, path: str):
    dump(obj, path)

def load_model(path: str):
    return load(path)

def predict_pipeline(pipeline, text: str) -> Tuple[int, float]:
    """Return (label, confidence). label 1=phish, 0=legit"""
    prob = pipeline.predict_proba([text])[0]
    pred = int(pipeline.predict([text])[0])
    conf = float(max(prob))
    return pred, conf
