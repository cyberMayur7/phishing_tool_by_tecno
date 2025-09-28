
# Simple Phishing Detector (URL + Email)

A small demo command-line phishing detection tool (Python).  
Includes training on tiny example datasets and a CLI to test URLs and emails.

## Files
- `phishing.py` — main tool
- `phishing_dataset.csv` — sample URL dataset
- `email_dataset.csv` — sample email dataset
- `requirements.txt` — needed Python packages

## Run (example)
```bash
python -m venv venv
# Windows
venv\Scripts\activate
# macOS / Linux
source venv/bin/activate

pip install -r requirements.txt
python phishing.py
