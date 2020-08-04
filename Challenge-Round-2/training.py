from sklearn.model_selection import RandomizedSearchCV
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import plot_confusion_matrix
from sklearn.svm import SVC
import pandas as pd
import numpy as np
import pickle


ben_df = pd.read_csv('final_benign.csv')
dos_df = pd.read_csv('final_ddos.csv')

y = [0 for _ in range(len(ben_df))]
y = np.append(y, [1 for _ in range(len(dos_df))])

X = pd.concat([ben_df, dos_df])

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.1)

svm = SVC()
svm_params = {'C':np.logspace(-3, 3, 7), 'gamma':np.logspace(-3, 3, 7)}
ssvm = RandomizedSearchCV(svm, svm_params, n_iter=20, verbose=2)

rfc = RandomForestClassifier()
rfc_params = {'n_estimators':[50, 100, 150, 200], 'max_depth':[3, 4, 5, 6]}
srfc = RandomizedSearchCV(rfc, rfc_params, n_iter=20, verbose=2)

