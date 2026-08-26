import pandas as pd

def count_statistics():
    cve_information = pd.read_pickle('total_results.pkl')
    counts = cve_information['CVE ID'].value_counts()
    print(counts)
    mean = counts.mean()
    median = counts.median()
    std_dev = counts.std()
    max = counts.max()
    min = counts.min()
    at_least_two_entries = (counts >= 2).sum() / len(counts) * 100
    print("Mean: ", mean)
    print("Median: ", median)
    print("Min: ", min)
    print("Max: ", max)
    print("Standard deviation: ", std_dev)
    print("At least two entries", at_least_two_entries)

if __name__ == "__main__":
    count_statistics()