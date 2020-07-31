from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import urllib.request
import pandas as pd
import numpy as np
import json


trainpath = 'https://mettl-arq.s3-ap-southeast-1.amazonaws.com/questions/iit-kanpur/cyber-security-hackathon/round1/problem2/xxl0d69v8w/training.json'

names = []
vals = []

with urllib.request.urlopen(trainpath) as url:
    data = json.loads(url.read().decode())
    for x in data:
        names.append(x.keys())
        vals.append(list(x.values())[0])

df = pd.DataFrame(vals[0], index=[0])

for i in range(len(vals)):
    z = (pd.DataFrame(vals[i], index=[i]))
    df = df.append(z)

df = df[1:]
df['Name'] = names

X = df.drop(['grade', 'Name'], axis=1)
y = df['grade']

X_train, X_valid, y_train, y_valid = train_test_split(X, y)

rfc = RandomForestClassifier(n_estimators=300, max_depth=7)
rfc.fit(X_train, y_train)

print('Train accuracy for the model is {}'.format(rfc.score(X_train, y_train)))
print('Validation accuracy for the model is {}'.format(rfc.score(X_valid, y_valid)))


testpath = 'https://mettl-arq.s3-ap-southeast-1.amazonaws.com/questions/iit-kanpur/cyber-security-hackathon/round1/problem2/xxl0d69v8w/testing.json'

names = []
vals = []

with urllib.request.urlopen(testpath) as url:
    data = json.loads(url.read().decode())
    for x in data:
        names.append(x.keys())
        vals.append(list(x.values())[0])

tdf = pd.DataFrame(vals[0], index=[0])
for i in range(len(vals)):
    z = (pd.DataFrame(vals[i], index=[i]))
    tdf = tdf.append(z)
tdf = tdf[1:]
tdf = tdf.drop(['grade'], axis=1)

n = []
for name in names:
    n.append(list(name)[0])
res = rfc.predict(tdf)
submission = dict(zip(n, res))

