import pickle

with open("total_extensions.pkl", "rb") as picklefile:
    total_extensions = pickle.load(picklefile)
    sorted_counts = sorted(total_extensions.items(), key = lambda x: x[1], reverse=True)
    top_10 = sorted_counts[:10]
    remaining = sum(count for _, count, in sorted_counts[10:])
    top_10.append(('Others', remaining))

    for item, count in top_10:
        print(f'{item}: {count}')