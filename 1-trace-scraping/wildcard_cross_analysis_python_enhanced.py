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

def analyze_imports(tree):
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for n in node.names:
                imports.add(n.name)
    return imports

def analyze_file(filename):
    variables = defaultdict(Counter)
    imported_modules = set()

    with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    try:
        tree = ast.parse(content)
        
        imported_modules = analyze_imports(tree)
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        category = categorize_variable(node.value)
                        variables[target.id][category] += 1
    except SyntaxError:
        print(f"Failed to parse {filename} due to syntax errors.")
        
    return variables, imported_modules

df = pd.read_pickle("total_results.pkl")

grouped = df.groupby('CVE ID')
filtered_df = df[df['CVE ID'].isin(grouped.filter(lambda x: len(x) > 1)['CVE ID'].unique())]
grouped = filtered_df.groupby('CVE ID')

KNOWN_MODULES = {"os", "sys", "glob", "re", "math", "time", "datetime", "ast", "collections", "pandas", "numpy"}

cve_variable_analysis = {}
for cve_id, group in grouped:
    cve_variables = defaultdict(Counter)
    all_imported_modules = set()

    for _, row in group.iterrows():
        foldername = os.path.join('total-folder', row['Foldername'])
        python_files = glob.glob(os.path.join(foldername, '*.py'), recursive=False)

        for file_path in python_files:
            variables, imports = analyze_file(file_path)
            all_imported_modules.update(imports)
            for var, counts in variables.items():
                cve_variables[var] += counts

    for variable in all_imported_modules:
        if variable in cve_variables and variable in KNOWN_MODULES:
            cve_variables[variable]["no wildcard"] += 1

    for variable, categories in cve_variables.items():
        total_counts = sum(categories.values())
        if categories["no wildcard"] > 0:
            if categories["no wildcard"] > total_counts / 2:
                categories["fully wildcard"] = 0
                categories["partial wildcard"] = 0

    cve_variable_analysis[cve_id] = cve_variables


global_count = {
    "fully wildcard": 0,
    "partial wildcard": 0,
    "no wildcard": 0
}

for _, variable_counter in cve_variable_analysis.items():
    for variable, categories in variable_counter.items():
        dominant_category = categories.most_common(1)[0][0]
        global_count[dominant_category] += 1

print(global_count)

    
