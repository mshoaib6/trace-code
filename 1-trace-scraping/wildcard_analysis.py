import pandas as pd
import os
import glob
import ast
import numpy as np


def categorize_variable(node):
    if isinstance(node, ast.Str):
        return "no wildcard"
    elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        if isinstance(node.left, ast.Str) or isinstance(node.right, ast.Str):
            return "partial wildcard"
    return "fully wildcard"


def analyze_file(filename):
    with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    categories_count = {
        "fully wildcard": 0,
        "partial wildcard": 0,
        "no wildcard": 0
    }

    try:
        tree = ast.parse(content)

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        category = categorize_variable(node.value)
                        categories_count[category] += 1
    except SyntaxError:
        print(f"Failed to parse {filename} due to syntax errors.")
        
    return categories_count


df = pd.read_pickle("total_results.pkl")

grouped = df.groupby('CVE ID')
filtered_df = df[df['CVE ID'].isin(grouped.filter(lambda x: len(x) > 1)['CVE ID'].unique())]

directories = filtered_df['Foldername'].tolist()

global_count = {
    "fully wildcard": 0,
    "partial wildcard": 0,
    "no wildcard": 0
}

for directory_name in directories:
    foldername = os.path.join('total-folder', directory_name)
    python_files = glob.glob(os.path.join(foldername, '*.py'), recursive=False)
    
    for file_path in python_files:
        result = analyze_file(file_path)
        for key, value in result.items():
            global_count[key] += value

print(global_count)