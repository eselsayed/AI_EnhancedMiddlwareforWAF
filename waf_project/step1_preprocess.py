import pandas as pd
import numpy as np
import urllib.parse
import base64
import re
import html
import argparse
import os

# NORMALIZATION 
"""Decode URL-encoded payloads"""
def url_decode(text: str) -> str:
    try:
        return urllib.parse.unquote(urllib.parse.unquote(text))  # double-decode
    except Exception:
        return text

"""Try to decode Base64-encoded segments inside the payload"""
def base64_decode(text: str) -> str:
    pattern = r'[A-Za-z0-9+/]{16,}={0,2}'
    def try_decode(m):
        try:
            decoded = base64.b64decode(m.group()).decode('utf-8', errors='ignore')
            return decoded if decoded.isprintable() else m.group()
        except Exception:
            return m.group()
    return re.sub(pattern, try_decode, text)

"""Decode HTML entities """
def html_decode(text: str) -> str:
    return html.unescape(text)

"""Decode hex-encoded characters """
def hex_decode(text: str) -> str:
    return re.sub(r'0x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), text)

"""Full normalization pipeline — exposes the true payload"""
def normalize(text: str) -> str:
    if not isinstance(text, str):
        text = str(text)
    text = url_decode(text)
    text = base64_decode(text)
    text = html_decode(text)
    text = hex_decode(text)
    text = text.lower().strip()
    return text



# LABEL MAPPING
LABEL_MAP = {
    'normal': 0, 'benign': 0, '0': 0, 0: 0,
    'sqli': 1, 'sql': 1, 'sql injection': 1, '1': 1, 1: 1,
    'xss': 2, 'cross-site scripting': 2, '2': 2, 2: 2,
}

def map_label(label):
    """Convert any label format to 0 / 1 / 2"""
    key = str(label).strip().lower()
    if key in LABEL_MAP:
        return LABEL_MAP[key]
    raise ValueError(f"Unknown label: '{label}'. Expected Normal/SQLi/XSS or 0/1/2")


# MAIN
def load_and_preprocess(csv_path: str) -> pd.DataFrame:
    print(f"\n[1/4] Loading dataset from: {csv_path}")
    df = pd.read_csv(csv_path)
    print(f"      Shape: {df.shape}")
    print(f"      Columns: {list(df.columns)}")

    # Auto-detect text column
    text_col = next((c for c in df.columns if c.lower() in ['sentence', 'query', 'payload', 'text', 'request']), df.columns[0])

    # ── Detect dataset format 
    cols_lower = [c.lower() for c in df.columns]

    # Format A: multi-column binary flags  (SQLInjection / XSS / Normal)
    sqli_col   = next((c for c in df.columns if 'sql' in c.lower()), None)
    xss_col    = next((c for c in df.columns if 'xss'  in c.lower()), None)
    norm_col   = next((c for c in df.columns if c.lower() == 'normal'), None)

    if sqli_col and xss_col:
        print(f"      Detected multi-column format: '{sqli_col}' / '{xss_col}'" +
              (f" / '{norm_col}'" if norm_col else ""))
        print("\n[2/4] Mapping labels → 0=Normal, 1=SQLi, 2=XSS")

        def encode_row(row):
            if int(float(row[sqli_col])) == 1:
                return 1   # SQLi
            elif int(float(row[xss_col])) == 1:
                return 2   # XSS
            else:
                return 0   # Normal

        df['label_encoded'] = df.apply(encode_row, axis=1)

    # Format B: single label column  (Normal / SQLi / XSS  or  0/1/2)
    else:
        label_col = next((c for c in df.columns if c.lower() in
                          ['label', 'class', 'type', 'category']), df.columns[-1])
        print(f"      Using  text='{text_col}'  label='{label_col}'")
        print("\n[2/4] Mapping labels → 0=Normal, 1=SQLi, 2=XSS")
        df['label_encoded'] = df[label_col].apply(map_label)

    counts = df['label_encoded'].value_counts().rename({0: 'Normal', 1: 'SQLi', 2: 'XSS'})
    print(counts.to_string())

    print("\n[3/4] Applying normalization layer (URL / Base64 / HTML / Hex decoding)")
    df['normalized'] = df[text_col].apply(normalize)

    print("\n[4/4] Saving preprocessed data → preprocessed_data.csv")
    out = df[['normalized', 'label_encoded']].rename(columns={'normalized': 'text', 'label_encoded': 'label'})
    out.to_csv('preprocessed_data.csv', index=False)
    print(f"      Saved {len(out)} rows.\n")
    return out


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--data', required=True, help='Path to the raw CSV dataset')
    args = parser.parse_args()
    load_and_preprocess(args.data)