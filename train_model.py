"""Train a message/SMS phishing text classifier from dataset/messages_dataset.csv."""
from pathlib import Path
import csv, sys
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, accuracy_score
import joblib

BASE=Path(__file__).resolve().parent
DATA=BASE/'dataset'/'messages_dataset.csv'
OUT=BASE/'models'/'message_model.joblib'

def main():
    texts=[]; labels=[]
    if not DATA.exists(): raise SystemExit(f'Dataset not found: {DATA}')
    with DATA.open('r',encoding='utf-8-sig',newline='') as f:
        reader=csv.DictReader(f)
        if not {'message','label'}.issubset(set(reader.fieldnames or [])):
            raise SystemExit('Dataset must contain message and label columns.')
        for row in reader:
            msg=(row.get('message') or '').strip(); label=(row.get('label') or '').strip().lower()
            if msg and label in {'phishing','legitimate'}: texts.append(msg); labels.append(label)
    if len(texts)<20: raise SystemExit('Dataset is too small; include at least 20 labelled examples.')
    print(f'Loaded {len(texts)} labelled messages.')
    print('Note: the included dataset is synthetic practice data. Results do not represent real-world detection accuracy.')
    X_train,X_test,y_train,y_test=train_test_split(texts,labels,test_size=0.2,random_state=42,stratify=labels)
    model=Pipeline([('tfidf',TfidfVectorizer(lowercase=True,ngram_range=(1,2),max_features=30000,sublinear_tf=True)),('classifier',LogisticRegression(max_iter=1200,class_weight='balanced'))])
    model.fit(X_train,y_train)
    pred=model.predict(X_test)
    print(f'Test accuracy on held-out synthetic examples: {accuracy_score(y_test,pred):.3f}')
    print(classification_report(y_test,pred,zero_division=0))
    OUT.parent.mkdir(exist_ok=True)
    joblib.dump(model,OUT)
    print(f'Model saved to: {OUT}')
    print('Keep in mind: synthetic data is for demonstrating the workflow, not proving production performance.')
if __name__=='__main__': main()
