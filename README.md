# Scanner

Simple scanner that loads the trained `MLP_Classifier.pkl` and `scaler.pkl` / `encoder.pkl` from the repository and runs predictions.

Usage examples:

CSV mode (use existing preprocessed KDD CSV):

```bash
python scanner.py --mode csv --input Dataset/kdd_test.csv --rows 100
```

Live capture (requires `scapy` and OS pcap driver like Npcap on Windows):

```bash
python scanner.py --mode live --duration 10
```

PCAP file mode:

```bash
python scanner.py --mode pcap --input capture.pcap
```

Notes:
- Live/pcap feature extraction is a basic heuristic that produces a small set of aggregate features (packet counts, bytes, unique IPs/ports). The trained model expects the same features used during training; if you used the original preprocessed features, pass CSV input.
- Install Npcap on Windows for live capture.