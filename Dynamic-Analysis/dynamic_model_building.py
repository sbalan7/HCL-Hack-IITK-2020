import pandas as pd
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


