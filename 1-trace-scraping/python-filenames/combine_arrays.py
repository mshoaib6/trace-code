import pickle
import os

filenames = []
i = 0

while os.path.isfile(f'python-filenames/pfa-{i}.pkl'):
    with open(f'python-filenames/pfa-{i}.pkl', 'rb') as f:
        array = pickle.load(f)
        print(len(array))
        print(type(array))
        print(array)
        filenames += [(item[0], '/'.join(item[0].split('/')[1:3])) for item in array if item]
    i += 1

with open(f'python-files.pkl', 'wb') as f:
    pickle.dump(filenames, f)

print(len(filenames))