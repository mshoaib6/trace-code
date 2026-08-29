import pandas as pd
import os
import glob
import ast
from collections import defaultdict

def get_potential_wildcards(node):
    wildcards = []
    if isinstance(node, ast.Str):
        return [node.s]
    elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        if isinstance(node.left, ast.Str):
            wildcards.append(node.left.s)
        if isinstance(node.right, ast.Str):
            wildcards.append(node.right.s)
    return wildcards

def analyze_file_for_wildcards(filename):
    wildcards = set()
    with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    try:
        tree = ast.parse(content)
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        wildcards.update(get_potential_wildcards(node.value))
    except SyntaxError:
        print(f"Failed to parse {filename} due to syntax errors.")
        
    return wildcards

def string_exists_in_file(potential_string, file_path):
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    return potential_string in content

df = pd.read_pickle("total_results.pkl")

grouped = df.groupby('CVE ID')
filtered_df = df[df['CVE ID'].isin(grouped.filter(lambda x: len(x) > 1)['CVE ID'].unique())]
grouped = filtered_df.groupby('CVE ID')

cve_wildcard_analysis = defaultdict(dict)
wildcard_count = {
    "fully wildcard": 0,
    "partial wildcard": 0,
    "no wildcard": 0
}

for cve_id, group in grouped:
    all_potential_strings = set()
    all_verified_strings = set()
    
    for _, row in group.iterrows():
        foldername = os.path.join('total-folder', row['Foldername'])
        python_files = glob.glob(os.path.join(foldername, '*.py'))
        
        for file_path in python_files:
            try:
                wildcards = analyze_file_for_wildcards(file_path)
                all_potential_strings.update(wildcards)
            except Exception as e:
                print(f"Error processing {file_path}: {e}")

        
        for file_path in python_files:
            wildcards = analyze_file_for_wildcards(file_path)
            all_potential_strings.update(wildcards)

    cve_wildcard_analysis[cve_id]['potential'] = all_potential_strings

    for potential_string in all_potential_strings:
        for _, row in group.iterrows():
            foldername = os.path.join('total-folder', row['Foldername'])
            files_to_check = glob.glob(os.path.join(foldername, '*.md')) + \
                             glob.glob(os.path.join(foldername, '*.txt')) + \
                             glob.glob(os.path.join(foldername, '*.py'))

            for file_path in files_to_check:
                if string_exists_in_file(potential_string, file_path):
                    all_verified_strings.add(potential_string)
                    break

    cve_wildcard_analysis[cve_id]['verified'] = all_verified_strings

    for string in all_potential_strings:
        if string in all_verified_strings:
            wildcard_count["fully wildcard"] += 1
        else:
            if "+" in string:
                wildcard_count["partial wildcard"] += 1
            else:
                wildcard_count["no wildcard"] += 1

print("Final counts:")
print(wildcard_count)


cve_verified_count = {cve: len(details['verified']) for cve, details in cve_wildcard_analysis.items()}
sorted_cves_by_verified = sorted(cve_verified_count.items(), key=lambda item: item[1], reverse=True)

print("\nTop 10 CVEs with Highest Number of Verified Wildcards:")
for i, (cve, count) in enumerate(sorted_cves_by_verified[:10]):
    print(f"{i+1}. {cve}: {count} verified wildcards")


unverified_cves = {cve: details['potential'] - details['verified'] for cve, details in cve_wildcard_analysis.items() if len(details['potential'] - details['verified']) > 0}

print("\nCVEs with Unverified Wildcards:")
for cve, unverified in unverified_cves.items():
    print(f"{cve}: {len(unverified)} unverified wildcards")


total_cves = len(cve_wildcard_analysis)
cves_with_verified = len([cve for cve, details in cve_wildcard_analysis.items() if details['verified']])
cves_without_verified = total_cves - cves_with_verified

print("\nGeneral Summary:")
print(f"Total CVEs analyzed: {total_cves}")
print(f"CVEs with at least one verified wildcard: {cves_with_verified}")
print(f"CVEs without any verified wildcards: {cves_without_verified}")
