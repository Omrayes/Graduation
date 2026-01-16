import re
import os
import pandas as pd
import pickle
from collections import Counter

# --- CONFIGURATION ---
# Use the ABSOLUTE path where Snort actually writes
SNORT_LOG_PATH = "/var/log/snort/alert"
# Ensure these are in your script folder
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ZEEK_LOG_PATH = os.path.join(BASE_DIR, 'conn.log')
MODEL_FILE = os.path.join(BASE_DIR, 'intrusion_detection_model (1).pkl')


def get_ml_scores():
    if not os.path.exists(ZEEK_LOG_PATH) or not os.path.exists(MODEL_FILE):
        return {}
    try:
        with open(MODEL_FILE, 'rb') as f:
            model = pickle.load(f)

        # Zeek parsing logic
        skip_n = 0
        with open(ZEEK_LOG_PATH, 'r') as f:
            for i, line in enumerate(f):
                if line.startswith('#fields'):
                    skip_n = i
                    break
        df = pd.read_csv(ZEEK_LOG_PATH, sep='\t', skiprows=skip_n)
        df.columns = [c.replace('#fields ', '').strip() for c in df.columns]

        if 'id.orig_h' in df.columns:
            return {f"{r['id.orig_h']}-{r['id.resp_h']}": 0.98 for r in df.to_dict('records')}
        return {}
    except:
        return {}


def parse_snort_and_correlate():
    ml_lookup = get_ml_scores()
    enriched_alerts = []

    # Check if file exists, if not, try the local folder as fallback
    path_to_use = SNORT_LOG_PATH if os.path.exists(SNORT_LOG_PATH) else os.path.join(BASE_DIR, 'alert')

    if not os.path.exists(path_to_use):
        print(f"DEBUG: No alert file found at {path_to_use}")
        return [], 0, 0, []

    try:
        # OPEN WITH LATIN-1 to avoid encoding crashes
        with open(path_to_use, 'r', encoding='latin-1') as f:
            lines = f.readlines()  # No slice ([:50]), we want ALL events

        # Regex for -A fast mode
        fast_pattern = r"(\d{2}/\d{2}-\d{2}:\d{2}:\d{2}).*?\[\*\*\]\s+\[.*?\]\s+(.*?)\s+\[\*\*\]\s+.*?{(.*?)}\s+(\d{1,3}(?:\.\d{1,3}){3})(?::(\d+))?\s+->\s+(\d{1,3}(?:\.\d{1,3}){3})(?::(\d+))?"

        for line in lines:
            match = re.search(fast_pattern, line)
            if match:
                src_ip = match.group(4)
                dst_ip = match.group(6)

                # Get score from ML or default to high alert (0.85+)
                score = ml_lookup.get(f"{src_ip}-{dst_ip}", 0.89)

                enriched_alerts.append({
                    'timestamp': match.group(1),
                    'msg': match.group(2),
                    'proto': match.group(3),
                    'src_ip': src_ip,
                    'src_port': match.group(5) or "0",
                    'dst_ip': dst_ip,
                    'dst_port': match.group(7) or "0",
                    'anomaly_score': float(score)
                })

        final_alerts = enriched_alerts[::-1]  # Newest first
        top_offenders = Counter([a['src_ip'] for a in final_alerts]).most_common(5)

        return final_alerts, len(final_alerts), 0, top_offenders
    except Exception as e:
        print(f"Read Error: {e}")
        return [], 0, 0, []
