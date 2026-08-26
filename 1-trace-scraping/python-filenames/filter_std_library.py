import pickle

with open('python-files.pkl', 'rb') as f:
    python_filenames = pickle.load(f)

new_function_counts = []
removed = []

for file in python_filenames:
    if '/python3.8/' not in file[0] and '/lib/' in file[0]:
        removed.append(file)
    else:
        new_function_counts.append(file)

print(len(python_filenames))
print(len(new_function_counts))
print(len(removed))
print(removed)