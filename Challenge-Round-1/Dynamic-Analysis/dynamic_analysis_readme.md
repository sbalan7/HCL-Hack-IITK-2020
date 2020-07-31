# Dynamic Malware Analysis with Machine Learning


### Introduction
The Dynamic data provided in the dataset was split into two categories. Despite the very large size of the dataset, there were few crucial feature vectors in the json files provided which give high classification accuracy. These feature vectors were extracted in the file `dynamic_model_building.py` and exported to a csv file. In the same file, a random forest was grown and used as the model to predict classes for the dynamic malware classification problem. The model achieves a perfect accuracy on a holdout validation set. The dynamic analysis model is then loaded into the final malware detection file for classification of unseen test set. 

### Libraries and Methods
 Efforts were taken to make the code platform independent with the use of the `os` library. The `dynamic_data_extract()` function reads the json file provided with the `json` library. It extracts data vectors from the file and stores it in a Pandas `DataFrame` object. This function is called over and over to recieve a dataline for prediction, which is then passed on the model. The model itself was a Random Forest Classifier with the `scikit-learn` implementation.

 The random forest classifier is dumped into the file `dynamic_model.dtc` with the `pickle` library. This will be loaded into the main file for classification.

 ### Observations
All files to be classified as malware have scan information with a lot of antivirus software having already found out if a hash is malicious or not. This is incomplete and inconclusive, for some vectors, however. Hence, the source of the file (encoded as 0 for none, and 1 for from the internet), its score and size were considered as additional features. However the sizes turn out to be a not so important feature for classification. The other features turn out to be relatively important, and go on to give a perfect classification.