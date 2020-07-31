from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import plot_confusion_matrix
from sklearn.preprocessing import LabelEncoder
import pandas as pd
import pickle
import json
import os

def dynamic_data_extract(path):
    dataline = pd.DataFrame()
    with open(path) as f:
        data = json.load(f)

        # Extract name hash
        try:
            x = data['target']['file']['sha256']
        except:
            print('File hash misssing for file {}'.format(path))
            x = 0
        finally:
            dataline['name'] = x

        # Extract scores
        try:
            x = data['info']['score']
        except:
            print('File score misssing for file {}'.format(path))
            x = 0
        finally:
            dataline['score'] = x

        # Extract size
        try:
            x = data['target']['file']['size']
        except:
            print('File size misssing for file {}'.format(path))
            x = 0
        finally:
            dataline['size'] = x

        # Extract source
        try:
            x = data['info']['route']
            if x == 'none':
                x = 0
            else:
                x = 1
        except:
            print('File route misssing for file {}'.format(path))
            x = 0
        finally:
            dataline['route'] = x
        
        if 'virustotal' in data.keys():
            dataline['virus'] = 1
        else:
            dataline['virus'] = 0

        if 'Benign' in path:
            dataline['target'] = 0
        else:
            dataline['target'] = 1

    return dataline

dynamic_root = ['Dynamic_Analysis_Data_Part1', 'Dynamic_Analysis_Data_Part2']
columns = ['name', 'score', 'size', 'route', 'virus', 'target']
df = pd.DataFrame(columns=columns)

for part in dynamic_root:
    b = os.path.join(part, 'Benign')
    m = os.path.join(part, 'Malware')
    
    ben_list = os.listdir(b)
    mal_list_ = os.listdir(m)
    
    for benign_file in ben_list:
        path = os.path.join(b, benign_file)
        dataline = dynamic_data_extract(path)
        df = pd.concat([df, dataline])
    
    for subdir in mal_list_:
        path_ = os.path.join(m, subdir)
        files = os.listdir(path_)
        for malware_file in files:
            path = os.path.join(path_, malware_file)
            dataline = dynamic_data_extract(path)
            df = pd.concat([df, dataline])

df.to_csv('dynamic_dataframe.csv', index=False)


le = LabelEncoder()
df['route'] = le.fit_transform(df['route'])
df['score'] = df['score'].astype(float)
df['size'] = df['size'].astype(int)
df['virus'] = df['virus'].astype(int)
df['target'] = df['target'].astype(int)
X = df.drop(['target', 'name'], axis=1)
y = df['target']
df.dtypes

X_train, X_valid, y_train, y_valid = train_test_split(X, y)

rfc = RandomForestClassifier(n_estimators=10)
rfc.fit(X_train, y_train)

model_path = 'dynamic_model.dtc'
pickle.dump(rfc, open(model_path, 'wb'))