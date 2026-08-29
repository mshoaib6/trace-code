

import pandas as pd
import os
import glob
from collections import defaultdict

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
    for member in group:
        foldername = os.path.join('total-folder', member['Foldername'])
        print(foldername)
        
        extensions = get_file_extensions(foldername)
        
        if member['CVE ID'] not in cve_languages:
            cve_languages[member['CVE ID']] = extensions
        else:
            for ext, count in extensions.items():
                cve_languages[member['CVE ID']][ext] += count

total_pocs = 0
cve_count = 0
for cve_id, languages in cve_languages.items():
    print(f"CVE ID: {cve_id}, Languages: {', '.join([f'{k}: {v}' for k, v in languages.items()])}")
    total_pocs += sum(languages.values())
    cve_count += 1

print(f"\nStatistics:")
print(f"Total number of CVEs: {cve_count}")
print(f"Total number of PoCs: {total_pocs}")
print(f"Average number of PoCs per CVE: {total_pocs / cve_count if cve_count != 0 else 0}")
