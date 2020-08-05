# CHALLENGE ROUND - 1 

This submission is by team "Python's got ping" by Dwij Mehta (dwij.mehta@gmail.com) and Shanmugha Balan (f20190571@pilani.bits-pilani.ac.in).


# Used Libraries
All the libraries used are standard. These include sklearn, xgboost for training and predictions.

The challenge round 1 features two types of data - static files and dynamic files. Feature extraction and model training was done separately for the types in their respective subdirectories. The final `MalwareDetection.py` file takes the best model trained from these two cases and also uses the same feature extraction functions. These script now iterates through all the files in the test directory and determines if it is a static type or dynamic type. It then passes the files to their respective functions which predict if the file is malware or benign. These are added to a DataFrame which will then be converted to a csv file. The final csv file is named as `submission.csv`.


# Static Data Analysis
Many keywords were identified to be of utmost importance for prediction using static data. These were taken from the structure_info.txt file. After that many words were identified to be repeating in the String.txt file so the 50 most common were extracted and feature vector was made using this for each training example. These were then trained on a gridsearchCV classifier using XGboost classifier as the base model.

# Dynamic Malware Analysis 

### Introduction
The Dynamic data provided in the dataset was split into two categories. Despite the very large size of the dataset, there were few crucial feature vectors in the json files provided which give high classification accuracy. These feature vectors were extracted in the file `dynamic_model_building.py` and exported to a csv file. In the same file, a random forest was grown and used as the model to predict classes for the dynamic malware classification problem. The model achieves a perfect accuracy on a holdout validation set. The dynamic analysis model is then loaded into the final malware detection file for classification of unseen test set. 

### Libraries and Methods
 Efforts were taken to make the code platform independent with the use of the `os` library. The `dynamic_data_extract()` function reads the json file provided with the `json` library. It extracts data vectors from the file and stores it in a Pandas `DataFrame` object. This function is called over and over to recieve a dataline for prediction, which is then passed on the model. The model itself was a Random Forest Classifier with the `scikit-learn` implementation.

 The random forest classifier is dumped into the file `dynamic_model.dtc` with the `pickle` library. This will be loaded into the main file for classification.

### Observations
All files to be classified as malware have scan information with a lot of antivirus software having already found out if a hash is malicious or not. This is incomplete and inconclusive, for some vectors, however. Hence, the source of the file (encoded as 0 for none, and 1 for from the internet), its score and size were considered as additional features. However the sizes turn out to be a not so important feat

# Results
The input pipeline was tried and tested on our local machines and it worked perfect acheiving an accuracy of 0.99 in Dynamic analysis and 0.985 in Static analysis.