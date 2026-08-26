import pickle
import sys

def get_list(name):
    with open(name, 'rb') as f:
        return pickle.load(f)
    
num = sys.argv[1]
    
list1 = get_list(f'python-filenames/pfa-{num}-old.pkl')
list2 = get_list(f'python-filenames/pfa-{num}.pkl')
# list3 = get_list('python-filenames/glob-python-files-9.pkl')
directories = get_list('directories.pkl')

print(len(list1))
print(len(list2))
# print(len(list3))

for i in range(len(list1)):
    if list1[i] != list2[i]:
        print(list1[i])
        print(list2[i])
        print(directories[0 + i])
        print()

newlist1 = [item for sublist in list1 for item in sublist]
newlist2 = [item for sublist in list2 for item in sublist]

print(newlist1 == newlist2)

with open(f'python-filenames/pfa-{num}-array.pkl', 'wb') as f:
    pickle.dump(newlist1, f)