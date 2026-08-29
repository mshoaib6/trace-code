import pickle

def get_list(name):
    with open(name, 'rb') as f:
        return pickle.load(f)
    
num = 3
    
dict1 = get_list(f'function_counts_new/{num}-data-1.pkl')['function_calls']
dict2 = get_list(f'function_counts_new/{num}-data-2.pkl')['function_calls']
print(dict1 == dict2)