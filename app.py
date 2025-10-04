# app.py
from flask import Flask, request, jsonify
from src.model import load_model, predict_pipeline

app = Flask(__name__)
model = load_model("models/url_model.pkl")

@app.route("/analyze", methods=["POST"])
def analyze():
    d = request.get_json() or {}
    url = d.get("url") or d.get("text")
    if not url:
        return jsonify({"error":"url/text missing"}), 400
    label, conf = predict_pipeline(model, url)
    return jsonify({"prediction": int(label), "confidence": conf})

if __name__ == "__main__":
    app.run(port=5000, debug=True)
