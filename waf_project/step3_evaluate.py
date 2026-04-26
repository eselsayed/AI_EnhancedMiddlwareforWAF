import pandas as pd
import numpy as np
import joblib
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    accuracy_score
)

CLASS_NAMES = ['Normal', 'SQLi', 'XSS']
THRESHOLD = 0.80

def apply_threshold(proba, threshold):
    predictions = np.zeros(len(proba), dtype=int)
    for i, p in enumerate(proba):
        max_conf = p.max()
        if max_conf >= threshold and p.argmax() != 0:
            predictions[i] = p.argmax()
        else:
            predictions[i] = 0
    return predictions

#confusion_matrix
def plot_confusion_matrix(y_true, y_pred):
    cm = confusion_matrix(y_true, y_pred)
    fig, ax = plt.subplots(figsize=(7, 5))
    sns.heatmap(
        cm, annot=True, fmt='d', cmap='Blues',
        xticklabels=CLASS_NAMES, yticklabels=CLASS_NAMES,
        linewidths=0.5, ax=ax,
        annot_kws={"size": 14, "weight": "bold"}
    )
    ax.set_xlabel('Predicted Label')
    ax.set_ylabel('True Label')
    ax.set_title('Confusion Matrix\n(Threshold = 80%)')
    plt.tight_layout()
    plt.savefig('confusion_matrix.png')
    plt.close()

#plot_threshold
def plot_threshold_experiment(y_true, proba):
    thresholds = np.arange(0.50, 1.00, 0.05)
    results = {c: [] for c in CLASS_NAMES}
    macro_f1 = []
    for t in thresholds:
        y_pred = apply_threshold(proba, t)
        f1s = f1_score(y_true, y_pred, average=None, labels=[0,1,2], zero_division=0)
        for i, c in enumerate(CLASS_NAMES):
            results[c].append(f1s[i])
        macro_f1.append(f1_score(y_true, y_pred, average='macro', zero_division=0))
    fig, ax = plt.subplots(figsize=(9, 5))
    for c in CLASS_NAMES:
        ax.plot(thresholds, results[c], marker='o', label=c)
    ax.plot(thresholds, macro_f1, marker='s', label='Macro F1', linestyle='--')
    ax.axvline(x=THRESHOLD, color='gray', linestyle=':')
    ax.set_xlabel('Confidence Threshold')
    ax.set_ylabel('F1-Score')
    ax.legend()
    plt.grid(True, alpha=0.3)
    plt.savefig('threshold_experiment.png')
    plt.close()

#  Tranning & test accuracy
def check_overfitting(model, vectorizer, test_df):
    train_df = pd.read_csv('preprocessed_data.csv')
    
    X_train = vectorizer.transform(train_df['text'].fillna(''))
    y_train = train_df['label'].values
    X_test = vectorizer.transform(test_df['text'].fillna(''))
    y_test = test_df['label'].values

    train_acc = accuracy_score(y_train, model.predict(X_train)) * 100
    test_acc = accuracy_score(y_test, model.predict(X_test)) * 100
    gap = train_acc - test_acc


def evaluate():
    model = joblib.load('model.pkl')
    vectorizer = joblib.load('vectorizer.pkl')
    test_df = pd.read_csv('test_split.csv')

    X_test = vectorizer.transform(test_df['text'].fillna(''))
    y_true = test_df['label'].astype(int).values

    proba = model.predict_proba(X_test)
    y_pred = apply_threshold(proba, THRESHOLD)

    print(classification_report(y_true, y_pred, target_names=CLASS_NAMES, digits=4))
    
    plot_confusion_matrix(y_true, y_pred)
    plot_threshold_experiment(y_true, proba)
    check_overfitting(model, vectorizer, test_df)

if __name__ == '__main__':
    evaluate()