from sklearn.model_selection import RandomizedSearchCV
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import plot_confusion_matrix
from sklearn.svm import SVC
import pandas as pd
import numpy as np
import pickle
from sklearn.preprocessing import LabelEncoder, MinMaxScaler
from feature_extract import proc_pcap_df
import os
import time

def get_csv_data():
    files = os.listdir('CSV files')
    files = []
    columns = ['avg_packet_len', 'avg_time_diff', 'dev_packet_len', 'dev_time_diff', 'unique_conns', 'percent_udp', 'src']
    final_df = pd.DataFrame(columns=columns)
    count = 0

    # iterate through files
    for f in files:
        tic = time.time()
        path = os.path.join('CSV files', f)
        try:
            data = pd.read_csv(path)
        except:
            print('File {} had an error and was not read'.format(path))
            continue
        
        if data.shape[0] == 0:
            print('File {} had an error and was not read'.format(path))
            continue
        data = proc_pcap_df(data, path, True)
        final_df = pd.concat([final_df, data])
        toc = time.time()
        count += 1
        print('{} Read {} in {} seconds'.format(count, path, toc-tic))

    return final_df

def get_training_Data(df):
    df.unique_conns = df.unique_conns.astype(int)
    
    def clean_dataset(df):
        assert isinstance(df, pd.DataFrame), "df needs to be a pd.DataFrame"
        df.dropna(inplace=True)
        indices_to_keep = ~df.isin([np.nan, np.inf, -np.inf]).any(1)
        return df[indices_to_keep].astype(np.float64)

    # remove potentially annoying values in data
    cleaned_df = clean_dataset(df.drop(['src'], axis=1))
    X = cleaned_df.drop(['target'], axis=1)
    y = cleaned_df['target']
    return X, y

def main():
    final_df = get_csv_data()

    X, y, cleaned_df = get_training_Data(final_df)

    mms = MinMaxScaler()
    X = mms.fit_transform(X)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.1)

    svm = SVC()
    tic = time.time()
    svm.fit(X_train, y_train)
    toc = time.time()
    print('Training took {} seconds'.format(toc-tic))
    svm.score(X_test, y_test)
    plot_confusion_matrix(svm, X_test, y_test)

    rfc_ = RandomForestClassifier()
    tic = time.time()
    rfc_.fit(X_train, y_train)
    toc = time.time()
    print('Training took {} seconds'.format(toc-tic))
    print(rfc_.score(X_test, y_test))
    plot_confusion_matrix(rfc_, X_test, y_test)

    pickle.dump(svm, open('magic_fn_svm.svm', 'wb'))
    pickle.dump(rfc_, open('magic_fn_rfc_wo_ip.rfc', 'wb'))

if __name__ == "__main__":
    main()