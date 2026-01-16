import datetime
import os
import pandas as pd
from datetime import datetime
import csv
import joblib
import numpy as np
from sniff import sniffing, RAW_LOG_FILE, CAPTURE_TIME
import socket

LOG_FILE = "./Logs/detection_log.csv"
# Load models
pipelineRF = joblib.load("./Model/RF_Pipeline.pkl")
pipelineXGBoost = joblib.load("./Model/XGBoost_Pipeline.pkl")

def extract_src_ip(flow_id: str) -> bool:
    current_ip = socket.gethostbyname(socket.gethostname())
    if current_ip.startswith("127.") or current_ip == "::1":
        # Attempt to get the actual external IP address
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 53))
            current_ip = s.getsockname()[0]
        except Exception:
            pass
    return current_ip==flow_id.split(":", 1)[0]

def predicting():
    # Sniff data
    flow_ids,X = sniffing()
    # standard run timestamp
    run_ts = datetime.now().isoformat()
    predictionXGBoost = pipelineXGBoost.predict(X)
    probabilityXGBoost = pipelineXGBoost.predict_proba(X)
    predictionRF = pipelineRF.predict(X)
    probabilityRF = pipelineRF.predict_proba(X)
    labels, counts = np.unique(predictionRF, return_counts=True)
    Y=[]
    L=len(flow_ids)
    for i in range(L):
        if (predictionRF[i]==1 or predictionXGBoost[i]==1) and not extract_src_ip(flow_ids[i]):
            Level="Attack"
            if (probabilityRF[i][1]>0.75 and probabilityXGBoost[i][1]>0.75) or (probabilityRF[i][1]>0.9 and probabilityXGBoost[i][1]<0.9) or (probabilityRF[i][1]<0.9 and probabilityXGBoost[i][1]>0.9):
                Level="High Attack"
            elif probabilityRF[i][1]>0.9 and probabilityXGBoost[i][1]>0.9:
                Level="Dangerous Attack"
            elif probabilityRF[i][1]>0.6 and probabilityXGBoost[i][1]>0.6:
                Level="Suspicious Behavior"
            else:
                Level="Low Attack"
            datas={"TimeStamp": run_ts, "Level": Level, "Flow ID": flow_ids[i], "Total": len(flow_ids), "Probability RF": float(probabilityRF[i][1]), "Probability XGBoost": float(probabilityXGBoost[i][1])}
            Y.append(datas)
    if len(Y)>0:
        file_exists = os.path.isfile(LOG_FILE)
        with open(LOG_FILE, "a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=Y[0].keys())
            if not file_exists:
                writer.writeheader()
            writer.writerows(Y)
    # compute per-run summary and append to sniff_summary.csv
    summary = {
        'TimeStamp': run_ts,
        'Packets': 0,
        'Flows': int(L),
        'Detected': len(Y),
        'Top_RF_Flow': '',
        'Top_RF_Prob': 0.0,
        'Top_XGB_Flow': '',
        'Top_XGB_Prob': 0.0
    }
    # count packets in RAW_LOG_FILE within CAPTURE_TIME window around run_ts
    try:
        run_epoch = datetime.fromisoformat(run_ts).timestamp()
    except Exception:
        run_epoch = None
    try:
        if run_epoch and os.path.isfile(RAW_LOG_FILE):
            with open(RAW_LOG_FILE, 'r', newline='') as fr:
                rreader = csv.DictReader(fr)
                for row in rreader:
                    try:
                        t = float(row.get('timestamp') or row.get('time') or 0)
                    except Exception:
                        continue
                    if abs(t - run_epoch) <= (CAPTURE_TIME * 2):
                        summary['Packets'] += 1
    except Exception:
        pass

    # find top probabilities among all flows
    try:
        if L > 0:
            # probability arrays may be numpy arrays
            rf_probs = [probabilityRF[i][1] for i in range(L)]
            xgb_probs = [probabilityXGBoost[i][1] for i in range(L)]
            # find indices of max
            idx_rf = int(np.nanargmax(rf_probs)) if len(rf_probs) > 0 else None
            idx_xgb = int(np.nanargmax(xgb_probs)) if len(xgb_probs) > 0 else None
            if idx_rf is not None:
                summary['Top_RF_Flow'] = flow_ids[idx_rf]
                summary['Top_RF_Prob'] = float(rf_probs[idx_rf])
            if idx_xgb is not None:
                summary['Top_XGB_Flow'] = flow_ids[idx_xgb]
                summary['Top_XGB_Prob'] = float(xgb_probs[idx_xgb])
    except Exception:
        pass

    # append summary CSV
    try:
        summary_file = './Logs/sniff_summary.csv'
        write_header = not os.path.isfile(summary_file)
        with open(summary_file, 'a', newline='') as fs:
            writer = csv.DictWriter(fs, fieldnames=list(summary.keys()))
            if write_header:
                writer.writeheader()
            writer.writerow(summary)
    except Exception:
        pass

    return summary