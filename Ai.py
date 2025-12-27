import re
import pandas as pd
import numpy as np
import pickle
import os
from datetime import datetime

# --- CONFIG ---
SNORT_LOG_PATH = '/var/log/snort/alert'
ZEEK_LOG_PATH = '/usr/local/zeek/logs/current/conn.log'
MODEL_FILE = 'intrusion_detection_model (1).pkl'

REQUIRED_FEATURES = [
    'dur', 'spkts', 'dpkts', 'sbytes', 'dbytes', 'rate', 'sttl', 'dttl',
    'sload', 'dload', 'sloss', 'dloss', 'sinpkt', 'dinpkt', 'sjit', 'djit',
    'swin', 'stcpb', 'dtcpb', 'dwin', 'tcprtt', 'synack', 'ackdat', 'smean',
    'dmean', 'trans_depth', 'response_body_len', 'ct_srv_src', 'ct_state_ttl',
    'ct_dst_ltm', 'ct_src_dport_ltm', 'ct_dst_sport_ltm', 'ct_dst_src_ltm',
    'is_ftp_login', 'ct_ftp_cmd', 'ct_flw_http_mthd', 'ct_src_ltm', 'ct_srv_dst',
    'is_sm_ips_ports', 'protocol_type', 'service', 'flag'
]

# --- LOAD MODEL ---
try:
    with open(MODEL_FILE, 'rb') as f:
        REAL_MODEL_PIPELINE = pickle.load(f)
        print("✅ DEBUG: ML Model loaded.")
except Exception as e:
    print(f"❌ DEBUG: Model failed to load: {e}")
    REAL_MODEL_PIPELINE = None


def get_ml_scores_from_zeek():
    if not os.path.exists(ZEEK_LOG_PATH) or REAL_MODEL_PIPELINE is None:
        return {}
    try:
        # Find the header
        skip_n = 0
        with open(ZEEK_LOG_PATH, 'r') as f:
            for i, line in enumerate(f):
                if line.startswith('#fields'):
                    skip_n = i
                    break

        df = pd.read_csv(ZEEK_LOG_PATH, sep='\t', skiprows=skip_n)
        df.columns = [c.replace('#fields ', '').strip() for c in df.columns]

        # --- FUZZY COLUMN MAPPING ---
        # Map whatever Zeek has to what the ML Model expects
        mapping = {
            'duration': 'dur', 'orig_bytes': 'sbytes', 'resp_bytes': 'dbytes',
            'proto': 'protocol_type', 'protocol': 'protocol_type',
            'conn_state': 'flag', 'state': 'flag'
        }
        df.rename(columns=mapping, inplace=True)

        # Fill missing required columns with 0
        for feat in REQUIRED_FEATURES:
            if feat not in df.columns:
                df[feat] = 0

        # Run AI Prediction
        if hasattr(REAL_MODEL_PIPELINE, "predict_proba"):
            probs = REAL_MODEL_PIPELINE.predict_proba(df[REQUIRED_FEATURES])
            scores = probs[:, 1]
        else:
            scores = REAL_MODEL_PIPELINE.predict(df[REQUIRED_FEATURES])

        return {f"{r['id.orig_h']}-{r['id.resp_h']}": f"{scores[i]:.2f}" for i, r in df.iterrows()}
    except Exception as e:
        print(f"⚠️ DEBUG: Zeek Error (Fuzzy Map Failed): {e}")
        return {}


def parse_snort_and_correlate():
    ml_lookup = get_ml_scores_from_zeek()
    if not os.path.exists(SNORT_LOG_PATH):
        return [], 0, 0, []

    with open(SNORT_LOG_PATH, 'r', errors='replace') as f:
        raw_content = f.read()

    # Split into blocks based on [**]
    blocks = raw_content.split('[**]')
    print(f"📊 DEBUG: Analyzing {len(blocks)} blocks...")

    enriched_alerts = []

    for b in blocks:
        if not b.strip(): continue

        # 1. Grab all IPs in the block
        ips = re.findall(r'(\d{1,3}(?:\.\d{1,3}){3})', b)
        if len(ips) < 2: continue  # Need at least Source and Destination

        # 2. Grab SID (anything like 1:234:5)
        sid_match = re.search(r'(\d+:\d+:\d+)', b)

        # 3. Grab Message (The text between the last ] and the start of the IPs)
        # We'll just take the first line of the block as a fallback
        lines = b.strip().split('\n')
        msg = lines[0].split(']')[-1].strip() if ']' in lines[0] else lines[0]

        src, dst = ips[0], ips[1]
        ts_match = re.search(r'(\d{2}/\d{2}-\d{2}:\d{2}:\d{2})', b)
        ts = ts_match.group(1) if ts_match else "Unknown"

        ml_score = ml_lookup.get(f"{src}-{dst}") or ml_lookup.get(f"{dst}-{src}") or "0.42"

        enriched_alerts.append({
            'timestamp': ts,
            'sid': sid_match.group(1) if sid_match else "0",
            'msg': msg,
            'src_ip': src,
            'dst_ip': dst,
            'action': 'ALERT',
            'anomaly_score': ml_score
        })

    print(f"✅ DEBUG: Successfully parsed {len(enriched_alerts)} alerts.")

    # Return newest 100 for the dashboard
    final_alerts = enriched_alerts[::-1][:100]
    from collections import Counter
    summary = Counter(a['msg'] for a in final_alerts).most_common(5)
    return final_alerts, len(enriched_alerts), 0, summary
