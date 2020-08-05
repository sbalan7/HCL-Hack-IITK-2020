# CHALLENGE ROUND - 2

This submission is by team "Python's got ping" by Dwij Mehta (dwij.mehta@gmail.com) and Shanmugha Balan (f20190571@pilani.bits-pilani.ac.in).

The challenge round 2 features a DDoS dataset. Network packet data is captured and presented in the form pcap files. The dataset contains __ pcap files with malicious packets used in a DDoS attack and __ pcap files which contain benign packets. The task is to classify the packets as ones used in a DDoS attack or benign given a pcap file. 

## Feature Extraction
Feature extraction was very challenging for the dataset which was very voluminous. The pcap files were composed of millions of packets which made extraction very slow. To this effect, the `dpkt` and `socket` packages were used. This made the training reasonably faster and allowed for extraction of information. Wireshark application was used to visualize the data. The entire pcap file's key information was transferred to a `DataFrame` object. This `DataFrame` was then further processed by grouping columns by Source's IP Address. This allowed us to compress a very huge `DataFrame` into a matter of 10-15 rows. 

The following features were then selected for each Source IP Address to act as a feature vector :-
1. Average Packet Size (avg_packet_len):
This feature was selected because it was found that a majority of attack packets seemed to have constant size of around 500 bytes. 

2. Average Time Difference Between Two Packets (avg_time_diff):
This feature was selected because in a benign traffic, the average time between two requests was much more than the average time between two requests in a DDOS attack traffic.

3. Standard Deviation of Packet Size:
This feature was engineered into the final `DataFrame` because it was found that in a DDOS attack, size of the packet's data was nearly constant. As a result, the deviation was 10 times lesser than the deviation of normal traffic.

4. Standard Deviation of Average Time Difference:
This feature was engineered into the final `DataFrame` because again it was found that in a DDOS attack, average time between requests do not fluctuate much. As a result, the deviation was 100-200 times lesser than the deviation of normal traffic.

5. Number of Unique Connections (unique_conns):
This feature represents the number of unique Destination IP addresses a Source IP address has communicated with. This was included because it was observed that in a DDOS attack, the Source IP address bombards a constant Destination IP address with data whereas in a normal traffic, the Source IP address communicates with a variety of Destination IP addresses.

6. Percentage of UDP Requests (percent_udp):
This feature is number of UDP requests made by a Source IP address divided by total number of requests made by that particular Source IP address. This was included in the `DataFrame` because it was found that `percent_udp` for DDOS attacks was higher than `percent_udp` for normal traffic.

## Model Selection
The data was split into training and validation data in a 9:1 ratio. The data was then evaluated through random forest and SVM algorithms. The SVM model trained much faster than the random forest models, but performed worse validation data. Random forests perfectly classify the train and validation data, but the SVM models only attain an accuracy of between 95% to 98% on train and validation. Random Forest models however continue to perform well, and achieve up to 90% accuracy on totally unseen test data.

![Model Selection](https://raw.githubusercontent.com/sbalan7/HCL-Hack-IITK-2020/master/Challenge-Round-2/Images/model_selection.png?token=ANTJ6F7YLWJENVQ4ZD7YFH27GPJME)

## Packages
For the purpose of this project, the following python packages were used. These packages can be installed with `pip`.

* scikit-learn (`pip install sklearn`)
* matplotlib (`pip install matplotlib`)
* pickle (`pip install pickle`)
* pandas (`pip install pandas`)
* numpy (`pip install numpy`)
* dpkt (`pip install dpkt`)
* sys
* os 
