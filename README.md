# PhishShift Message Risk Scanner

A beginner-friendly Flask web application with exactly three tools:

1. **Message / SMS scanner** — uses a trained TF-IDF + Logistic Regression model and gives understandable warning reasons and safer next steps.
2. **CSV scanner** — batch scans a CSV containing a `message`, `text`, `sms`, `email`, or `content` column and lets you download results.
3. **URL analyzer** — checks visible URL structure for common warning signs. It does **not** open the URL or check live reputation.

## Dataset

`dataset/messages_dataset.csv` and `dataset/messages_dataset.xlsx` contain 2,500 **synthetic educational examples** (1,250 labelled phishing and 1,250 labelled legitimate). They are not real emails and should not be used to claim real-world accuracy. Use an appropriately licensed, representative, privacy-reviewed dataset before evaluating for real use.

## Setup on Windows

Use Python 3.12 if possible. Open CMD in the folder that contains `app.py`:

```bat
py -3.12 -m venv .venv
.venv\Scripts\activate.bat
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python train_model.py
python app.py
```

Then open **http://127.0.0.1:5000**.

If `py -3.12` is not available, install Python 3.12 from the official Python website. If Windows reports `An Application Control policy has blocked this file` while importing compiled libraries, this is a Windows security/policy issue; do not disable protections or download DLLs from third-party sites. Ask your device administrator or Windows support to review the specific block. This app uses Flask rather than Streamlit, but model training still requires scikit-learn's compiled dependencies.

## CSV format

```csv
message
"Your account is locked. Verify details now at http://example.invalid"
"Reminder: our meeting starts at 2 PM."
```

## Important limitations

- The included training data is synthetic and repetitive; model outputs are demonstrations, not proof.
- A low-risk prediction does not prove safety. A phishing message may look professional and a legitimate message may contain urgent wording.
- URL checks are heuristic only and do not perform DNS, certificate, malware, or reputation checks.
- Never paste passwords, OTPs, payment details, or private recovery tokens into a scanner.
