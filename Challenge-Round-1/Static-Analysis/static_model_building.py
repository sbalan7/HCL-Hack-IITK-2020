import pandas as pd
from sklearn.metrics import plot_confusion_matrix, accuracy_score
import pickle
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import plot_confusion_matrix
import matplotlib.pyplot as plt
import numpy as np
import time
import xgboost as xgb
from xgboost import XGBClassifier
from sklearn.model_selection import GridSearchCV


def get_data():
  # Gets data from a csv file. The csv files were
  # created by running the feature_extraction script on 
  # static data analysis directory.
    
  df_Malware = pd.read_csv("Static_Analysis_Data-Malware.csv")
  df_Malware.drop("Unnamed: 0", inplace=True, axis=1)

  df1 = pd.read_csv("Static_Analysis_Data-Malware-EngineeredFeatures.csv")
  df_Malware = df_Malware.merge(df1)
  df = pd.read_csv("CommonWords-Malware.csv")
  df.drop("Unnamed: 0", inplace=True, axis=1)
  df_Malware = df_Malware.merge(df, on="name")
  df_Malware["target"] = [1 for i in range(len(df_Malware))]

  df_benign = pd.read_csv("Static_Analysis_Data-Benign.csv")
  df_benign.drop("Unnamed: 0", inplace=True, axis=1)

  df1 = pd.read_csv("Static_Analysis_Data-Benign-EngineeredFeatures.csv")
  df_benign = df_benign.merge(df1)
  df = pd.read_csv("CommonWords-Benign.csv")
  df.drop("Unnamed: 0", inplace=True, axis=1)
  df_benign = df_benign.merge(df, on="name")
  df_benign["target"] = [0 for i in range(len(df_benign))]
  data = pd.concat([df_benign, df_Malware])

  return data

data = get_data()

# Drops Hash column and a redundant index column
data = data.drop(['name', 'Unnamed: 0'], axis=1)

le = LabelEncoder()
X = data.drop(['target'], axis=1)
y = data['target']
cols = X.columns
for col in cols:
    # Leave entropy column as it is
    if col != "Entropy:":
      X[col] = le.fit_transform(X[col].astype(str))


from sklearn.model_selection import train_test_split
X_train, X_valid, y_train, y_valid = train_test_split(X, y, test_size=0.2)

xgb_model = xgb.XGBClassifier()

# Setting parameters for gridsearch
parameters = {'nthread':[4], #when use hyperthread, xgboost may become slower
              'objective':['binary:logistic'],
              'learning_rate': [0.05], #so called `eta` value
              'max_depth': [6],
              'silent': [1],
              'subsample': [0.8],
              'colsample_bytree': [0.7],
              'n_estimators': [1000], #number of trees, change it to 1000 for better results
              'seed': [42],
              'gamma': [1]}

# Create a gridsearch model using parameters and 
# AUC as the scoring criterion and binary:logistic objective
# function.
clf = GridSearchCV(xgb_model, parameters, n_jobs=5, 
                    # cv=(X_valid, y_valid), 
                   scoring='roc_auc',
                   verbose=2, refit=True)

clf.fit(X_train, y_train)

pickle.dump(clf, open("model_gridsearch.sav", 'wb'))