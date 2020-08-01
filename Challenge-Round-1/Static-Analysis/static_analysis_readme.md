# STATIC MALWARE ANALYSIS

### Introduction
THe static analysis is done with two scripts, the `static_model_building.py`, and `feature_extraction.py`. The feature extraction file extracts features from the data by iterating through the `string.txt` and `structure_info.txt` files. The data is saved in a pandas dataframe and exported to csv. This is now read and used to train a Random Forest Classifier and XGBoost Classifier, who's hyperparameters are evaluated with Grid Search. The model achieves upto 98% accuracy on a validation set.

### Libraries
sklearn
xgboost
numpy
pandas
pickle
collections
os
string

