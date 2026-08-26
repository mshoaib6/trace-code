import pickle

def get_list(name):
    with open(name, 'rb') as f:
        return pickle.load(f)
    
list1 = get_list('python-filenames/pfa-10-old.pkl')
list2 = get_list('python-filenames/pfa-10.pkl')
# list3 = get_list('python-filenames/old-9-2.pkl')
# list4 = get_list('python-filenames/old-6-3.pkl')
print(len(list1))
print(len(list2))
# print(len(list3))
# print(len(list4))

print(list1 == list2)