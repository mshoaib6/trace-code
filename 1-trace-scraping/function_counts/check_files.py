import pickle

def get_list(name):
    with open(name, 'rb') as f:
        return pickle.load(f)
    
num = 3
    
dict1 = get_list(f'function_counts_new/{num}-data-1.pkl')['function_calls']
dict2 = get_list(f'function_counts_new/{num}-data-2.pkl')['function_calls']
# list3 = get_list('python-filenames/old-9-2.pkl')
# list4 = get_list('python-filenames/old-6-3.pkl')
# print(len(list1))
# print(len(list2))
# print(len(list3))
# print(len(list4))
print(dict1 == dict2)