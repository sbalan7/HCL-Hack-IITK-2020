import pandas as pd
from sklearn.preprocessing import LabelEncoder

df = pd.read_csv('dynamic_dataframe.csv')
le = LabelEncoder()
df['route'] = le.fit_transform(df['route'])
df.to_csv('dynamic_dataframe.csv', index=False)