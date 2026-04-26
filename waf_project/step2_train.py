import pandas as pd
import numpy as np
import joblib
import os

from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
 
 
# CONFIG
INPUT_CSV    = 'preprocessed_data.csv'   # output of step1
TEST_SIZE    = 0.20                       # 80/20 split
RANDOM_STATE = 42
N_ESTIMATORS = 200
CLASS_NAMES  = ['Normal', 'SQLi', 'XSS']

# TF-IDF — character n-grams work better than word n-grams for payloads
TFIDF_PARAMS = dict(
    analyzer    = 'char_wb',   # character-level with word boundaries
    ngram_range = (2, 5),      # bi-grams to 5-grams
    max_features= 30_000,
    sublinear_tf= True,        # log(tf) instead of raw tf — reduces impact of common tokens
    min_df      = 2,
)



# MAIN
def train():
    # 1. Load preprocessed data
    print("[1/5] Loading preprocessed_data.csv …")
    df = pd.read_csv(INPUT_CSV)
    X = df['text'].fillna('')
    y = df['label'].astype(int)
    print(f"      Total samples : {len(df)}")
    for i, name in enumerate(CLASS_NAMES):
        print(f"      {name:<10} : {(y == i).sum()}")

    # 2. Train/test split 
    print("\n[2/5] Splitting → 80% train / 20% test (stratified) …")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )
    print(f"      Train: {len(X_train)}  |  Test: {len(X_test)}")

    # 3. TF-IDF vectorization
    print("\n[3/5] Fitting TF-IDF vectorizer (char_wb, 2-5 grams) …")
    vectorizer = TfidfVectorizer(**TFIDF_PARAMS)
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec  = vectorizer.transform(X_test)
    print(f"      Feature matrix: {X_train_vec.shape}")

    # 4. Train Random Forest
    print("\n[4/5] Training Random Forest …")
    model = RandomForestClassifier(
        n_estimators  = N_ESTIMATORS,
        class_weight  = 'balanced',   # critical for false-positive control
        max_depth     = None,
        min_samples_leaf = 1,
        n_jobs        = -1,
        random_state  = RANDOM_STATE,
    )
    model.fit(X_train_vec, y_train)
    print("      Training complete ")

    # 5. Save artifacts
    print("\n[5/5] Saving model artifacts …")
    joblib.dump(model,      'model.pkl')
    joblib.dump(vectorizer, 'vectorizer.pkl')

    # Also save test split for evaluation
    test_df = pd.DataFrame({'text': X_test.values, 'label': y_test.values})
    test_df.to_csv('test_split.csv', index=False)



if __name__ == '__main__':
    train()
