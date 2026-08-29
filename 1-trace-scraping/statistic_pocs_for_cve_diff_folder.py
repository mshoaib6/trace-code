import pandas as pd
import os
import glob
from collections import defaultdict
from collections import Counter

df = pd.read_pickle("total_results.pkl")

grouped = df.groupby('CVE ID')
filtered_df = df[df['CVE ID'].isin(grouped.filter(lambda x: len(x) > 1)['CVE ID'].unique())]

directories = filtered_df['Foldername'].tolist()
grouped = filtered_df.groupby('CVE ID')

group_array = []
for _, group in grouped:
    group_data = group.to_dict('records')
    group_array.append(group_data)

def get_file_extensions(directory):
    extensions = defaultdict(int)
    for filepath in glob.glob(os.path.join(directory, '*'), recursive=False):
        if os.path.isfile(filepath):
            extensions[os.path.splitext(filepath)[1]] += 1
    return extensions

cve_languages = {}

for group in group_array:
    cve_id = group[0]['CVE ID']
    cve_languages[cve_id] = []
    for member in group:
        foldername = os.path.join('total-folder', member['Foldername'])
        print(foldername)
        
        extensions = get_file_extensions(foldername)
        
        cve_languages[cve_id].append(extensions)

for cve_id, languages_list in cve_languages.items():
    print(f"\nCVE ID: {cve_id}")
    for i, languages in enumerate(languages_list):
        print(f"Folder {i+1}: {', '.join([f'{k}: {v}' for k, v in languages.items()])}")

    if len(languages_list) > 1:
        diff = set(languages_list[0].keys()) ^ set(languages_list[1].keys())
        common = set(languages_list[0].keys()) & set(languages_list[1].keys())
        print(f"Differential Analysis: Different languages used: {', '.join(diff)}")
        print(f"Common languages used: {', '.join(common)}")

total_ext_counts = []

for cve_id, languages_list in cve_languages.items():
    unique_exts = set()
    for lang_dict in languages_list:
        unique_exts.update(lang_dict.keys())
    total_ext_counts.append(len(unique_exts))

stat_series = pd.Series(total_ext_counts)

mean_count = stat_series.mean()
median_count = stat_series.median()
min_count = stat_series.min()
max_count = stat_series.max()

print(f"\nDistribution of different PoC file types for CVEs with >1 PoC:")
print(f"Mean: {mean_count}")
print(f"Median: {median_count}")
print(f"Min: {min_count}")
print(f"Max: {max_count}")

all_diff_extensions = []
all_common_extensions = []

for cve_id, languages_list in cve_languages.items():
    if len(languages_list) > 1:
        diff = set(languages_list[0].keys()) ^ set(languages_list[1].keys())
        common = set(languages_list[0].keys()) & set(languages_list[1].keys())
        all_diff_extensions.extend(list(diff))
        all_common_extensions.extend(list(common))

diff_counter = Counter(all_diff_extensions)
common_counter = Counter(all_common_extensions)

top_10_diff = diff_counter.most_common(10)

top_10_common = common_counter.most_common(10)

print("\nTop 10 Differential Extensions:")
for ext, count in top_10_diff:
    print(f"{ext}: {count} times")

print("\nTop 10 Common Extensions:")
for ext, count in top_10_common:
    print(f"{ext}: {count} times")