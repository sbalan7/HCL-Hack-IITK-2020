# CHALLENGE ROUND - 2

This submission is by team "Python's got ping" by Dwij Mehta (dwij.mehta@gmail.com) and Shanmugha Balan (f20190571@pilani.bits-pilani.ac.in).

The challenge round 2 features a DDoS dataset. Network packet data is captured and presented in the form pcap files. The dataset contains __ pcap files with malicious packets used in a DDoS attack and __ pcap files which contain benign packets. The task is to classify the packets as ones used in a DDoS attack or benign given a pcap file. 

### Feature Extraction
Feature extraction was very challenging for the dataset which was very voluminous. The pcap files were composed of millions of packets which made extraction very slow. To this effect, the `dpkt` and `socket` packages were used. This made the training reasonably faster and allowed for extraction of information. As referenced in the paper, ___, features found to be useful were ____. These were then exported to a csv file via a pandas `DataFrame` object. 

### Model Selection
The data was split into training and validation data in a 9:1 ratio. The data was then evaluated through random forest and SVM algorithms.