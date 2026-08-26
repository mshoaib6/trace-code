import pandas as pd
import os
import glob
import ast
from collections import defaultdict, Counter

def categorize_variable(node):
    if isinstance(node, ast.Str):  # hardcoded string
        return "no wildcard"
    elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        # Check for concatenation
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
        
        # Collect imports
        imported_modules = analyze_imports(tree)
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):  # variable assignment
                for target in node.targets:
                    if isinstance(target, ast.Name):  # simple variable assignment
                        category = categorize_variable(node.value)
                        variables[target.id][category] += 1
    except SyntaxError:
        print(f"Failed to parse {filename} due to syntax errors.")
        
    return variables, imported_modules

df = pd.read_pickle("total_results.pkl")

grouped = df.groupby('CVE ID')
filtered_df = df[df['CVE ID'].isin(grouped.filter(lambda x: len(x) > 1)['CVE ID'].unique())]
grouped = filtered_df.groupby('CVE ID')

# List of well-known Python modules that we can trust as "no wildcard"
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

    # After analyzing all PoCs for a CVE, update the variable types based on imports
    for variable in all_imported_modules:
        if variable in cve_variables and variable in KNOWN_MODULES:
            cve_variables[variable]["no wildcard"] += 1

    # Cross-reference variables across PoCs for the same CVE
    for variable, categories in cve_variables.items():
        total_counts = sum(categories.values())
        # If the variable is ever classified as "no wildcard", we can adjust our wildcard assessment
        if categories["no wildcard"] > 0:
            # If it's "no wildcard" in more than half the instances, then let's categorize it as "no wildcard"
            if categories["no wildcard"] > total_counts / 2:
                categories["fully wildcard"] = 0
                categories["partial wildcard"] = 0

    cve_variable_analysis[cve_id] = cve_variables

# From here we can continue to aggregate, print or otherwise manipulate the cve_variable_analysis data as needed.

# Aggregate the results
global_count = {
    "fully wildcard": 0,
    "partial wildcard": 0,
    "no wildcard": 0
}

for _, variable_counter in cve_variable_analysis.items():
    for variable, categories in variable_counter.items():
        dominant_category = categories.most_common(1)[0][0]
        global_count[dominant_category] += 1

# Print the aggregated results
print(global_count)

# # Now, let's dive deeper into specific CVEs
# for cve_id, variable_counter in cve_variable_analysis.items():
#     print(f"\nAnalysis for CVE ID: {cve_id}")
    
#     for variable, categories in variable_counter.items():
#         print(f"Variable: {variable}")
#         for category, count in categories.items():
#             print(f"\t{category}: {count}")

# # more specific results, like the most common variables categorized as wildcards across all CVEs:
# wildcard_variables = defaultdict(int)

# for _, variable_counter in cve_variable_analysis.items():
#     for variable, categories in variable_counter.items():
#         wildcard_variables[variable] += categories["fully wildcard"]

# print("\nTop 10 wildcard variables:")
# for variable, count in sorted(wildcard_variables.items(), key=lambda x: x[1], reverse=True)[:10]:
#     print(f"{variable}: {count} times")


