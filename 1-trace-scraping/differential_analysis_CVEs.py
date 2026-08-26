import pandas as pd
import os
import glob
from collections import defaultdict
import ast

# Function to extract all string literals from a Python file
def extract_strings_from_python(file_path):
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
        tree = ast.parse(file.read())
    return [node.s for node in ast.walk(tree) if isinstance(node, ast.Str)]

# Function to check if any of the strings are present in a file and calculate match percentage
def check_strings_in_file(file_path, strings):
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
        data = file.read()
    matching_strings = [string for string in strings if string in data]
    match_percentage = (len(matching_strings) / len(strings)) * 100 if strings else 0
    return match_percentage, matching_strings

# Main script
df = pd.read_pickle("total_results.pkl")

grouped = df.groupby('CVE ID')
filtered_df = df[df['CVE ID'].isin(grouped.filter(lambda x: len(x) > 1)['CVE ID'].unique())]

group_array = []
for _, group in grouped:
    group_data = group.to_dict('records')
    group_array.append(group_data)

for group in group_array:
    cve_id = group[0]['CVE ID']
    print(f"\nAnalyzing CVE ID: {cve_id}")

    for member in group:
        foldername = os.path.join('total-folder', member['Foldername'])
        python_files = glob.glob(os.path.join(foldername, '*.py'), recursive=False)

        if len(python_files) == 1:
            print(f"Analyzing folder: {foldername}")
            strings_to_check = extract_strings_from_python(python_files[0])

            # Check these strings in all other folders for the same CVE
            for other_member in group:
                if other_member != member:
                    other_foldername = os.path.join('total-folder', other_member['Foldername'])
                    print(f"Comparing with folder: {other_foldername}")

                    for file_path in glob.glob(os.path.join(other_foldername, '*'), recursive=True):
                        if os.path.isfile(file_path):
                            match_percentage, matching_strings = check_strings_in_file(file_path, strings_to_check)
                            if match_percentage > 0:
                                print(f"Found {match_percentage:.2f}% matching strings in file: {file_path}")

