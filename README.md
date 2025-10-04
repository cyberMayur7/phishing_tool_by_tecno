# Phishing Tool

## Quick start
1. python -m venv venv
2. .\venv\Scripts\activate
3. pip install -r requirements.txt
4. python train.py --csv data/sample.csv --out models/url_model.pkl
5. python -m src.cli --model models/url_model.pkl
