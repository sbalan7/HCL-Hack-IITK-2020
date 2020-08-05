import pandas as pd
import pickle
import socket
import dpkt
import sys
import os


def inet_to_str(inet):
    # Convert inet object to a string
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

def pcap_to_dict(pcap):
    # PCAP data list for saving all packets 
    pcap_data = []
    ip_dict = {}
    for ts, buf in pcap:
        
        pcap_dict = {}
        eth = dpkt.ethernet.Ethernet(buf)
        
        # If packet IP is not ethernet type then it is skipped
        if eth.type!=dpkt.ethernet.ETH_TYPE_IP:
            continue
        ip = eth.data
        tcp = ip.data
        dst = ip.dst
        dst = inet_to_str(dst)

        src = ip.src
        src = inet_to_str((src)) 
        pcap_dict["len"] = ip.len
        pcap_dict["dst"] = dst
        pcap_dict["src"] = src
        
        src = str(src) 

        # The next 3 condtions are to check whether the 
        # source has sent more than 15k requests or not.
        # If yes only then it will be added to dataframe.
        # This condtion halves the data size without considerable 
        # effect on model performance. 
        if src not in ip_dict.keys():
            ip_dict[src] = 0
            continue
        else:
            ip_dict[src] = ip_dict[src] + 1

        if ip_dict[src] < 15000:
            continue

        # Timestamp added to dataframe
        pcap_dict["timestamp"] = ts
        
        # Conditions to check communication Protocol
        if ip.p not in (dpkt.ip.IP_PROTO_TCP, dpkt.ip.IP_PROTO_UDP):
            pcap_dict["proto"] = "Other"
            continue

        if  ip.p == dpkt.ip.IP_PROTO_TCP:
            pcap_dict["proto"] = "TCP" 
        elif ip.p == dpkt.ip.IP_PROTO_UDP:
            pcap_dict["proto"] = "UDP"
        else:
            pcap_dict["proto"] = None

        pcap_data.append(pcap_dict)

    return pcap_data


# Magic Function
def proc_pcap_df(df):
    srcs = df["src"].unique()
    df["diff"] = df.timestamp.diff()
    df = df.fillna(0)
    df.drop("timestamp", axis=1, inplace=True)
    data = []

    def conv_proto(proto):
        if proto == "UDP":
            return 1
        else:
            return 0

    df["proto"] = df["proto"].apply(conv_proto)
    
    for src in srcs:
        udp_count = df.loc[df["src"] == src].proto.sum()
        total = df.loc[df["src"] == src].proto.count()

        temp = df.loc[df["src"] == src]
        temp = temp.fillna(0)
        
        stats = temp.describe()
        
        temp = temp.groupby("src").mean()
        temp = temp.to_dict(orient="list")
        
        temp["dev_packet_len"] = stats["len"]["std"]
        temp["dev_time_diff"] = stats["diff"]["std"]
        temp["unique_conns"] = df.loc[df["src"] == src].dst.nunique()
        temp["percent_udp"] = float(udp_count)/float(total)
        temp["src"] = src
        data.append(temp)

    df = pd.DataFrame(data)

    # These column values were coming as a list of 1 value so we used only first value
    df["len"] = df["len"].apply(lambda x: x[0])
    df["diff"] = df["diff"].apply(lambda x: x[0])
    df.drop("proto", axis=1, inplace=True)
    
    try:
        df.drop("Unnamed: 0", axis=1, inplace=True)
    except KeyError:
        pass

    df = df.rename(columns={"len": "avg_packet_len", "diff": "avg_time_diff"})
    return df


# Load the classifier
path_to_classifier = ''
model = pickle.load(open(path_to_classifier))

# Read the pcap passed to file
filename = sys.argv[1]
with open(filename, 'rb') as f:
    pcap = dpkt.pcap.Reader(f)

# Preprocess data
pcap_dict = pcap_to_dict(pcap)
df = pd.DataFrame(pcap_dict)
final_df = proc_pcap_df(df)

# Predict
preds = model.predict(final_df)
ips = # How to get the IP addresses???
result = dict(zip(ips, preds))

# Write result
with open('submission.txt', 'w') as f:
    f.write(result)
