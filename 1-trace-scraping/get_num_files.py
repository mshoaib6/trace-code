import pickle
from pandas import read_pickle
import os
import glob
import sys

def get_python_files():
    filenames = []
    df = read_pickle('total_results.pkl')
    if not os.path.isfile('directories.pkl'):
        directories = df['Foldername'].tolist()
        f1 = open('directories.pkl', 'wb')
        pickle.dump(directories, f1)
        f1.close()
    else:
        with open('directories.pkl', 'rb') as f:
            directories = pickle.load(f)
    print(len(directories))
    length=1000

    if len(sys.argv) != 2:
        print("Usage: python3 get_python_files.py [index]")
        return
    
    array_index = int(sys.argv[1])
    if array_index * length > len(directories):
        print("Index out of bounds of filename array")
        return

    print("indices: ", array_index * length, (array_index + 1) * length)
    directories = directories[array_index * length:(array_index + 1) * length]

    # parse_file('total-folder/poc-in-gh/poc-in-gh-3030/cve-2019-2725.py', function_calls)

    for dir in directories:
        filenames.append(len(glob.glob(os.path.join("total-folder", dir, '**/*.py'), recursive=True)))
    
    # if not os.path.exists("python-filenames"):
    #     os.makedirs("python-filenames")
    
    output_file = os.path.join('python-filenames/lengths', f'pfa-{array_index}-length.pkl')
    
    with open(output_file, 'wb') as f:
        pickle.dump(filenames, f)

if __name__ == "__main__":
    get_python_files()