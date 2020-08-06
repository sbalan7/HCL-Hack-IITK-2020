from feature_extract import proc_pcap_df, pcap_to_dict
import pandas as pd
import datetime
import pickle
import socket
import dpkt
import sys
import os
import time

# Load the classifier and scaler
path_to_classifier = 'Models/magic_fn_rfc_wo_ip.rfc'
path_to_scaler = 'Models/mms.pkl'
print("Getting pickled model...")
model = pickle.load(open(path_to_classifier, "rb"))
mms = pickle.load(open(path_to_scaler, "rb"))

# Read the pcap passed to file
filename = sys.argv[1]
f = open(filename, 'rb')
print("Opening the PCAP file...")
pcap = dpkt.pcap.Reader(f)

# Preprocess data
print("Preprocessing the PCAP file...")
t = time.time()
pcap_dict = pcap_to_dict(pcap)
df = pd.DataFrame(pcap_dict)
final_df = proc_pcap_df(df)
print(f"Preprocessing took {time.time() - t} seconds")

# Predict
print("Now predicting...")
X = final_df.drop(['src'], axis=1)
X = mms.transform(X)
ips = final_df["src"]
t = time.time()
preds = model.predict(X)
print(f"Predicting took {time.time() - t} seconds")

f.close()

# Write result
print("Writing to submission.txt file...")
with open(r'submission.txt', 'w') as f:
    for i, r in enumerate(preds):
        if r == 1:
            time = df.loc[df["src"] == ips[i]].timestamp.mean()
            avg = datetime.datetime.fromtimestamp(time)
            f.write(f"DDOS Attack detected from IP Address {ips[i]} at around {avg.strftime('%Y-%m-%d %H:%M:%S')}!! \n")
        else:
            f.write(f"Traffic from {ips[i]} is perfectly fine. No worries! \n")
