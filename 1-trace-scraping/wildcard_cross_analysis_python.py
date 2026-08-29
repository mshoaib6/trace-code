import pandas as pd
import os
import glob
import ast
from collections import defaultdict, Counter


def categorize_variable(node):
    if isinstance(node, ast.Str):
        return "no wildcard"
    elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        if isinstance(node.left, ast.Str) or isinstance(node.right, ast.Str):
            return "partial wildcard"
    return "fully wildcard"


def analyze_file(filename):
    variables = defaultdict(list)

    with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    try:
        tree = ast.parse(content)
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        category = categorize_variable(node.value)
                        variables[target.id].append(category)
    except SyntaxError:
        print(f"Failed to parse {filename} due to syntax errors.")
        
    return variables


df = pd.read_pickle("total_results.pkl")

grouped = df.groupby('CVE ID')
filtered_df = df[df['CVE ID'].isin(grouped.filter(lambda x: len(x) > 1)['CVE ID'].unique())]

grouped = filtered_df.groupby('CVE ID')

cve_variable_analysis = defaultdict(lambda: defaultdict(Counter))

for cve_id, group in grouped:
    for _, row in group.iterrows():
        foldername = os.path.join('total-folder', row['Foldername'])
        python_files = glob.glob(os.path.join(foldername, '*.py'), recursive=False)
        
        for file_path in python_files:
            variables = analyze_file(file_path)
            for variable, types in variables.items():
                cve_variable_analysis[cve_id][variable].update(types)

final_counts = {
    "fully wildcard": 0,
    "partial wildcard": 0,
    "no wildcard": 0
}

for cve_id, variable_data in cve_variable_analysis.items():
    for variable, types in variable_data.items():
        if types["no wildcard"] > 0:
            final_counts["no wildcard"] += 1
        elif types["partial wildcard"] > 0:
            final_counts["partial wildcard"] += 1
        else:
            final_counts["fully wildcard"] += 1

print(final_counts)