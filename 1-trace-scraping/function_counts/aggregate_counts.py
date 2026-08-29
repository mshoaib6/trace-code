import pickle
import pandas as pd
import os


total = 0
failed = 0
python2 = 0
function_calls = {}
dirs = []

def merge_dicts(dict1, dict2):
    dict = {}
    for key in dict1:
        dict[key] = dict.get(key, 0) + dict1[key]
    for key in dict2:
        dict[key] = dict.get(key, 0) + dict2[key]
    return dict

for i in range(20):
    if not os.path.isfile(f'function_counts/{i}-data.pkl'):
        continue
    with open(f'function_counts/{i}-data.pkl', 'rb') as f:
        data = pickle.load(f)
        function_calls  = merge_dicts(data['function_calls'], function_calls)
        total += data['total']
        failed += data['failed']
        python2 += data['python2']
        dirs.append(data['failed_dirs'])

with open(f'function_counts/function_counts_new.pkl', 'wb') as f:
    pickle.dump(function_calls, f)

total_df = pd.concat(dirs, ignore_index=True)
total_df.to_pickle('function_counts/failed_dirs_new.pkl')

print('total: ', total)
print('failed: ', failed)
print('python2: ', python2)