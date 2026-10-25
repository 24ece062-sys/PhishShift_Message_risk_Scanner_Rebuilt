from flask import Flask, render_template, request, jsonify, send_file
from pathlib import Path
import csv, io, re, json, ipaddress
from urllib.parse import urlparse, unquote
import joblib

BASE = Path(__file__).resolve().parent
MODEL_PATH = BASE / 'models' / 'message_model.joblib'
app = Flask(__name__)
_model = None

def load_model():
    global _model
    if _model is None and MODEL_PATH.exists():
        _model = joblib.load(MODEL_PATH)
    return _model

PHISHING_SIGNS = [
    (r'\b(urgent|immediately|final warning|act now|within \d+ minutes|limited time)\b', 'Uses urgency or a deadline to pressure you into acting before checking.'),
    (r'\b(password|login details|sign.?in|credentials)\b', 'Asks you to sign in or provide account credentials through a message.'),
    (r'\b(otp|one.?time password|verification code|cvv|pin)\b', 'Mentions a secret code or payment security detail. Never share OTPs, PINs or CVVs.'),
    (r'\b(locked|suspended|blocked|deleted|closure|lose access)\b', 'Threatens account suspension or loss of access to make you panic.'),
    (r'\b(prize|won|winner|reward|free gift|claim)\b', 'Promises a prize or reward that may be used as bait.'),
    (r'\b(refund|tax refund|bonus|withdraw|pending payment)\b', 'Uses a refund, bonus or payment claim to encourage you to disclose details.'),
    (r'\b(kyc|redelivery fee|unpaid fine|pay.*fee)\b', 'Requests an unexpected payment or identity/KYC update.'),
    (r'https?://|www\.', 'Contains a link. Do not open it until you independently verify the sender and domain.')
]

def explain_message(text, label, probability=None):
    reasons=[]
    for pattern, reason in PHISHING_SIGNS:
        if re.search(pattern, text, re.I): reasons.append(reason)
    if label == 'phishing' and not reasons:
        reasons.append('The text resembles patterns learned from labelled phishing examples; this is a warning signal, not proof by itself.')
    if label == 'legitimate':
        reasons = [r for r in reasons if 'Contains a link' not in r and 'Never share' not in r]
        reasons.append('No strong phishing pattern was detected by this model. This does not guarantee the message is safe.')
    return reasons

def scan_message(text):
    text=(text or '').strip()
    if not text: return {'error':'Enter a message or SMS to scan.'}, 400
    model=load_model()
    if model is None:
        return {'error':'The model is not trained yet. Run: python train_model.py'}, 503
    pred=model.predict([text])[0]
    probs=model.predict_proba([text])[0]
    classes=list(model.classes_)
    phishing_prob=float(probs[classes.index('phishing')]) if 'phishing' in classes else 0.0
    label='phishing' if pred=='phishing' else 'likely legitimate'
    return {'label':label,'risk':'High risk' if label=='phishing' else 'Lower risk','confidence':round(phishing_prob*100,1),'reasons':explain_message(text, 'phishing' if label=='phishing' else 'legitimate'),'advice':('Do not click the link, reply, call numbers in the message, download attachments, or share passwords/OTP/PIN/CVV/bank details. Verify through the official app, a saved bookmark, or a phone number you already trust.' if label=='phishing' else 'Still be careful: check the sender and destination independently. Never share passwords, OTPs, PINs or CVVs. Open official apps or type a known website address yourself.')}

def analyze_url(raw):
    raw=(raw or '').strip()
    if not raw: return {'error':'Enter a URL to analyze.'},400
    if not re.match(r'^https?://',raw,re.I): raw='http://' + raw
    try: p=urlparse(raw)
    except Exception: return {'error':'That URL could not be parsed.'},400
    host=(p.hostname or '').lower().rstrip('.')
    if not host: return {'error':'Enter a URL with a valid hostname, such as example.com.'},400
    reasons=[]; score=0
    if p.scheme.lower()!='https': score+=1; reasons.append('The URL does not use HTTPS. Traffic may not be encrypted; HTTPS alone does not prove a site is trustworthy.')
    try:
        ipaddress.ip_address(host); score+=2; reasons.append('The host is an IP address rather than a recognizable domain name.')
    except ValueError: pass
    if '@' in p.netloc: score+=2; reasons.append('The URL contains an @ symbol in its authority section, which can disguise the actual destination.')
    if len(raw)>100: score+=1; reasons.append('The URL is unusually long, which can obscure the real destination.')
    if host.count('-')>=3: score+=1; reasons.append('The domain contains several hyphens, which can be a warning sign in deceptive domains.')
    if host.count('.')>=4: score+=1; reasons.append('The hostname has many subdomain levels. Check the registrable domain carefully.')
    if any(x in host for x in ['verify','secure','login','account','update','claim','prize','wallet','support','kyc','refund']):
        score+=1; reasons.append('The domain uses words commonly seen in account-verification or reward-themed lures. This alone is not proof of fraud.')
    if p.scheme.lower() not in ('http','https'): score+=2; reasons.append('The URL uses an unexpected protocol.')
    if not reasons: reasons.append('No obvious structural warning signs were found by these simple checks. This is not a reputation or malware scan.')
    risk='High risk' if score>=4 else ('Caution' if score>=2 else 'Lower apparent risk')
    return {'url':raw,'hostname':host,'risk':risk,'score':score,'reasons':reasons,'advice':'This tool does not visit the URL or check live domain reputation. Do not enter credentials or payment details. Verify the domain independently and use an official app or saved bookmark.'},200

@app.get('/')
def home(): return render_template('index.html')
@app.post('/api/scan-message')
def api_message():
    data = request.get_json(silent=True) or request.form
    result = scan_message(data.get('message', ''))

    if isinstance(result, tuple):
        response, status = result
        return jsonify(response), status

    return jsonify(result), 200
@app.post('/api/analyze-url')
def api_url():
    data=request.get_json(silent=True) or request.form
    result,status=analyze_url(data.get('url',''))
    return jsonify(result),status
@app.post('/api/scan-csv')
def api_csv():
    file=request.files.get('file')
    if not file: return jsonify({'error':'Choose a CSV file first.'}),400
    try: text=file.stream.read().decode('utf-8-sig')
    except UnicodeDecodeError: return jsonify({'error':'Could not read this file as UTF-8 CSV. Save it as CSV UTF-8 and try again.'}),400
    reader=csv.DictReader(io.StringIO(text))
    if not reader.fieldnames: return jsonify({'error':'The CSV must have a header row and a message/text column.'}),400
    fields={f.lower().strip():f for f in reader.fieldnames}
    col=next((fields[k] for k in ('message','text','sms','email','content') if k in fields),None)
    if not col: return jsonify({'error':'Add a column named message, text, sms, email, or content.'}),400
    model=load_model()
    if model is None: return jsonify({'error':'The model is not trained yet. Run: python train_model.py'}),503
    output=[]
    for i,row in enumerate(reader, start=2):
        msg=(row.get(col) or '').strip()
        if not msg: continue
        pred=model.predict([msg])[0]
        probs=model.predict_proba([msg])[0]; classes=list(model.classes_)
        pp=float(probs[classes.index('phishing')]) if 'phishing' in classes else 0.0
        output.append({'row':i,'message':msg,'label':'Phishing' if pred=='phishing' else 'Likely legitimate','phishing_probability':round(pp*100,1),'reasons':' | '.join(explain_message(msg,'phishing' if pred=='phishing' else 'legitimate'))})
        if len(output)>=5000: break
    return jsonify({'count':len(output),'phishing':sum(1 for x in output if x['label']=='Phishing'),'results':output})
@app.get('/health')
def health(): return jsonify({'ok':True,'model_ready':MODEL_PATH.exists()})
if __name__=='__main__': app.run(debug=True, host='127.0.0.1', port=5000)
