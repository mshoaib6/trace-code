import pandas as pd
import os
import pycode_similar
import autopep8
from lib2to3 import refactor
import ast
import lib2to3
import glob
import numpy as np

df = pd.read_pickle("total_results.pkl")

grouped = df.groupby('CVE ID')
filtered_df = df[df['CVE ID'].isin(grouped.filter(lambda x: len(x) > 1)['CVE ID'].unique())]

# print(filtered_df[['CVE ID', 'Foldername']].sort_values(by = 'CVE ID'))

directories = filtered_df['Foldername'].tolist()
grouped = filtered_df.groupby('CVE ID')

group_array = []
for _, group in grouped:
    group_data = group.to_dict('records')
    group_array.append(group_data)

fixer_names = refactor.get_fixers_from_package('lib2to3.fixes')
fixer = refactor.RefactoringTool(fixer_names)

total_results = []
for group in group_array:
    group_files = []
    for member in group:
        foldername = os.path.join('total-folder', member['Foldername'])  
        print(foldername)
        python_files = glob.glob(os.path.join(foldername, '*.py'), recursive=False)
        if len(python_files) == 0:
            print(member['Foldername'], ' does not have python files')
            continue
        else:
            total_file = ""
            for file in python_files:
                try:
                    try:
                        with open(file, 'r') as file:
                            data = file.read()
                    except UnicodeDecodeError:
                        with open(file, 'rb') as file:
                            data = file.read().decode('utf-8')
                except (UnicodeDecodeError, TypeError) as error: 
                    print("File Unicode Decode Error")
                    continue
                total_file += data + "\n"
            group_files.append(total_file)
    
    if (len(group_files)) < 2:
        print("Less than two python files exist for CVE")
        continue

    reference = group_files[0]
    results = []
    for remaining in group_files[1:]:
        try:
            try:
                try:
                    ast.parse(reference)
                except SyntaxError:
                    reference = str(fixer.refactor_string(reference, 'reference'))
                    ast.parse(reference)
            except TabError:
                reference = autopep8.fix_code(reference)
            try:
                try:
                    ast.parse(remaining)
                except SyntaxError:
                    remaining = str(fixer.refactor_string(remaining, 'reference'))
                    ast.parse(remaining)
            except TabError:
                remaining = autopep8.fix_code(remaining)
        except (lib2to3.pgen2.parse.ParseError, lib2to3.pgen2.tokenize.TokenError, IndentationError) as error:
            print("Bad parse")
            continue
        similarity = pycode_similar.detect([reference, remaining], diff_method=pycode_similar.TreeDiff, keep_prints=False, module_level=True)
        #     except SyntaxError:
        #             autopep8.fix_code(reference)
        #             autopep8.fix_code(remaining)
        #             fixer_names = refactor.get_fixers_from_package('lib2to3.fixes')
        #             fixer = refactor.RefactoringTool(fixer_names)
        #             data = str(fixer.refactor_string(data, filename))
        #             similarity = pycode_similar.detect([reference, remaining], diff_method=pycode_similar.TreeDiff, keep_prints=False, module_level=True)
        # except TabError:
        #     normalized_code = autopep8.fix_code(reference)
        #     normalized_code = autopep8.fix_code(remaining)
        #     similarity = pycode_similar.detect([reference, remaining], diff_method=pycode_similar.TreeDiff, keep_prints=False, module_level=True)
        results.append(similarity[0][1][0].plagiarism_percent)
        # if (similarity[0][1][0].plagiarism_percent > 0.8 and similarity[0][1][0].plagiarism_percent < 0.95):
        #     print(similarity[0][1][0])
        #     print("reference\n\n", reference)
        #     print("\n\n\n\n")
        #     print("remaining:\n\n", remaining)
        #     exit(0)
        total_results.extend(results)
    print(results)

total_results = np.array(total_results)
print("Mean: ", total_results.mean())
print("Median: ", np.median(total_results))
print("Min: ", total_results.min())
print("Max: ", total_results.max())
print("Standard Deviation: ", total_results.std())