import os
import ast
from pandas import read_pickle
from datetime import datetime
import pickle
import lib2to3
from lib2to3 import refactor
import ast
import autopep8
import pandas as pd
import sys
import builtins
import copy
import json

def recur_through_attributes(node):
    if isinstance(node, ast.Name):
        return node.id
    elif isinstance(node, ast.Attribute):
        remainder = recur_through_attributes(node.value)
        if remainder:
            return remainder + "." + node.attr
        return None
    elif isinstance(node, ast.Call):
        remainder = recur_through_attributes(node.func)
        if remainder:
            return remainder + "()"
        return None
    else:
        return None
    # else:
    #     print("ERROR: Unrecognized node type")
    #     print(ast.dump(node))
    #     print(ast.unparse(node))
    #     exit(1)

def has_earlier_function_call(node):
    if isinstance(node, ast.Name):
        return False
    elif isinstance(node, ast.Call) or isinstance(node, ast.Subscript):
        return True
    elif isinstance(node, ast.Attribute):
        return has_earlier_function_call(node.value)

def has_call_in_tree(node):
    for subnode in ast.walk(node):
        if isinstance(subnode, ast.Call):
            return True
    return False

def module_alias_match(attribute_chain, key):
    return attribute_chain.startswith(key) and (len(attribute_chain) == len(key) or attribute_chain[len(key)] == '.')

def all_calls(node):
    if isinstance(node, ast.Name):
        return True
    elif isinstance(node, ast.Attribute):
        if isinstance(node.value, ast.Call):
            return all_calls(node.value)
        return False
    elif isinstance(node, ast.Call):
        return all_calls(node.func)

def get_attribute_name(node, function_mapping):
    attribute_chain = recur_through_attributes(node.value)
    if attribute_chain:
        if "()" in attribute_chain:
            first_call = attribute_chain.split("()")[0]
            if first_call in function_mapping:
                attribute_chain = attribute_chain.replace(first_call, function_mapping[first_call])
        if all_calls(node):
            return attribute_chain + "." + node.attr
        else:
            if attribute_chain:
                for key in function_mapping:
                    if module_alias_match(attribute_chain, key):
                        attribute_chain = attribute_chain.replace(key, function_mapping[key], 1)
                        return attribute_chain + "." + node.attr
    return node.attr

        # print("ERROR! ATTRIBUTE NAME")
        # print("print node dump:\n\n")
        # print(ast.dump(node))

def process_call_node(node, function_mapping, variable_mapping):
    node = map_variables_and_remove_call_arguments(node, variable_mapping)
    if isinstance(node.func, ast.Name):
        function_name = node.func.id
        if function_name in function_mapping:
            function_name = function_mapping[function_name]
    elif isinstance(node.func, ast.Attribute):
        function_name = get_attribute_name(node.func, function_mapping)
    else:
        function_name = None
    # elif isinstance(node.func, ast.BinOp) or isinstance(node.func, ast.Call) or isinstance(node.func, ast.Subscript) or isinstance(node.func, ast.IfExp) or isinstance(node.func, ast.Constant):
    #     function_name = None
    # else:
    #     print('error')
    #     print(ast.unparse(node))
    #     print(ast.dump(node))
    #     exit(1)
    
    if function_name:
        function_name += "()"
    return function_name

def is_user_defined_module(foldername, module_name):
    foldername = os.path.join('total-folder', foldername)
    module_name = '/'.join(module_name.split('.'))
    file_path = os.path.join(foldername, module_name + ".py")
    return os.path.exists(file_path)

def function_is_relevant(function_name, user_defined_functions, user_defined_modules_and_functions, function_mapping):
    # Case 0: None returned
    if not function_name:
        return False
    # Case 1: User-defined function
    if function_name in user_defined_functions:
        return False
    # Case 2: Built-in function
    if function_name in builtins.__dict__.keys():
        return True
    # Case 3: User-defined file
    if "." in function_name:
        for module in user_defined_modules_and_functions:
            if function_name.startswith(module) and (function_name == module or (len(function_name) > len(module) and function_name[len(module)] == '.')):
                return False
    # Case 4: Library import or function call on object 
    return True
    # if function_name in function_mapping.values():
    #     return True
    # for key in function_mapping:
    #     if function_name.startswith(function_mapping[key]) and function_name[len(function_mapping[key])] == '.':
    #         return True
    # print("Unknown case?")
    # print(function_name)
    # print(user_defined_functions)
    # print(user_defined_modules_and_functions)
    # print(function_mapping)
    # exit(1)
    # file_path = os.path.join(script_directory, import_name + ".py")
    # return os.path.exists(file_path)
    
class NodeReplacer(ast.NodeTransformer):
    def __init__(self, variable_mapping):
        self.variable_mapping = variable_mapping

    def visit(self, node):
        if isinstance(node, ast.Name) and node.id in self.variable_mapping:
            # Replace the node with the new node
            return self.variable_mapping[node.id]
        elif isinstance(node, ast.Call):
            nodes_to_remove = set()
            for arg in node.args:
                if not has_call_in_tree(arg):
                    nodes_to_remove.add(arg)
            for arg in nodes_to_remove:
                node.args.remove(arg)

        # If the condition is not met, continue traversing the AST
        return self.generic_visit(node)

# replaces all variables with current_mapping and returns node
def map_variables_and_remove_call_arguments(value, variable_mapping):
    value = copy.deepcopy(value)
    replacer = NodeReplacer(variable_mapping=variable_mapping)
    value = replacer.visit(value)
    return value
    # else:
    #     print("Cannot map variables")
    #     print("Dump: ", ast.dump(value))
    #     print("Unparse: ", ast.unparse(value))
    #     exit(1)

def parse_file(filename, foldername):
    global failed, python2, failed_dirs, index, function_calls
    print(filename)
    try:
        try:
            with open(filename, 'r') as file:
                data = file.read()
        except UnicodeDecodeError:
            with open(filename, 'rb') as file:
                data = file.read().decode('utf-8')
    except UnicodeDecodeError: 
        failed += 1
        with open('function-call-log.txt', 'a') as file:
                file.write('unicode decode error: ' + str(filename)+'\n')
        failed_dirs.loc[index, 'Foldername'] = foldername
        index += 1
        return

    try:
        try:
            tree = ast.parse(data)
        except SyntaxError:
                autopep8.fix_code(data)
                fixer_names = refactor.get_fixers_from_package('lib2to3.fixes')
                fixer = refactor.RefactoringTool(fixer_names)
                data = str(fixer.refactor_string(data, filename))
                tree = ast.parse(data)
                python2 += 1
    except TabError:
        normalized_code = autopep8.fix_code(data)
        tree = ast.parse(normalized_code)
    except (lib2to3.pgen2.parse.ParseError, lib2to3.pgen2.tokenize.TokenError, IndentationError, SyntaxError) as error:
        failed += 1
        with open('function-call-log.txt', 'a') as file:
            file.write('syntax error: ' + str(filename) + '\n')
            file.close()
        failed_dirs.loc[index, 'Foldername'] = foldername
        index += 1
        return

    return parse_tree(tree, foldername, filename)

def parse_string(string_to_parse):
    tree = ast.parse(string_to_parse)
    foldername = '.'
    filename = 'idek'
    function_calls = {}

    # remove all call arguments from AST
    return parse_tree(tree, foldername, filename)

def parse_tree(tree, foldername, filename):
    global syscalls
    total = 0
    # mapping of functions/aliases to modules and original function names
    function_mapping = {}
    # set of user defined functions within a file
    user_defined_functions = set()
    # set of modules defined by users
    user_defined_modules_and_functions = set()
    # mapping of variable names to complete statements
    variable_mapping = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    function_mapping[alias.asname] = alias.name
                else:
                    function_mapping[alias.name] = alias.name
                if is_user_defined_module(foldername, alias.name):
                        user_defined_modules_and_functions.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                # relative import case ???
                if alias.asname:
                    if node.module:
                        function_mapping[alias.asname] = node.module + "." + alias.name
                        if is_user_defined_module(foldername, node.module):
                            user_defined_modules_and_functions.add(node.module + "." + alias.name)
                    else:
                        print('node ', ast.unparse(node))
                        print('filename ', filename)
                        print("error: relative import")
                        exit(1)
                        function_mapping[alias.asname] = alias.name
                        if is_user_defined_module(foldername, alias.name):
                            user_defined_modules_and_functions.add(alias.name)
                else:
                    if node.module:
                        function_mapping[alias.name] = node.module + "." + alias.name
                        if is_user_defined_module(foldername, node.module):
                            user_defined_modules_and_functions.add(node.module + "." + alias.name)
                    else:
                        print('node ', ast.unparse(node))
                        print('filename ', filename)
                        print("error: relative import")
                        exit(1)
                        function_mapping[alias.name] = alias.name
                        if is_user_defined_module(foldername, node.module):
                            user_defined_modules_and_functions.add(alias.name)
        elif isinstance(node, ast.FunctionDef):
            user_defined_functions.add(node.name + "()")
    # print(function_mapping)
    # print(user_defined_functions)
    # print(user_defined_modules_and_functions)
    
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    variable_name = target.id
                    mapped_expression = map_variables_and_remove_call_arguments(node.value, variable_mapping)
                    variable_mapping[variable_name] = mapped_expression
                elif isinstance(target, ast.Tuple):
                    for element in target.elts:
                        if isinstance(element, ast.Name):
                            variable_name = element.id
                            mapped_expression = map_variables_and_remove_call_arguments(node.value, variable_mapping)
                            variable_mapping[variable_name] = mapped_expression
                        # elif not isinstance(element, ast.Attribute) and not isinstance(element, ast.Starred) and not isinstance(element, ast.Tuple):
                        #     print("Unrecognized tuple member")
                        #     print("Dump: ", ast.dump(target))
                        #     print("Unparse: ", ast.unparse(target))
                        #     exit(1)
                # elif not isinstance(target, ast.Attribute) and not isinstance(target, ast.Subscript):
                #     print("Unrecognized node type")
                #     print("Dump: ", ast.dump(node))
                #     print("Unparse: ", ast.unparse(node))
                #     print("Target dump: ", ast.dump(target))
                #     print("Target unparse: ", ast.unparse(target) )
                #     exit(1)
        elif isinstance(node, ast.AugAssign):
            if isinstance(node.target, ast.Name):
                variable_name = node.target.id
                mapped_expression = map_variables_and_remove_call_arguments(node.value, variable_mapping)
                variable_mapping[variable_name] = mapped_expression
            elif not isinstance(node.target, ast.Attribute) and not isinstance(node.target, ast.Subscript):
                print("Unrecognized node type")
                print("Dump: ", ast.dump(node))
                print("Unparse: ", ast.unparse(node))
                exit(1)
        elif isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name):
                variable_name = node.target.id
                type = ast.parse(ast.unparse(node.annotation) + "()").body[0].value
                variable_mapping[variable_name] = type
        elif isinstance(node, ast.With):
            for item in node.items:
                # if len(node.items) == 1 and isinstance(node.items[0].context_expr, ast.Call):
                if isinstance(item.context_expr, ast.Call):
                    function = item.context_expr
                    if item.optional_vars:
                        if isinstance(item.optional_vars, ast.Name):
                            variable_mapping[item.optional_vars.id] = function
                        else:
                            print("Unrecognized optional_vars type")
                            print("Dump: ", ast.dump(node))
                            print("Unparse: ", ast.dump(node))
                            exit(1)
                # else:
                #     print("context expression unrecognized node type")
                #     print("Dump: ", ast.dump(node))
                #     print("Unparse: ", ast.unparse(node))
                #     exit(1)
        if isinstance(node, ast.Call):
            function_name = process_call_node(node, function_mapping, variable_mapping)
            
            # Check that function isn't user defined
            if function_is_relevant(function_name, user_defined_functions, user_defined_modules_and_functions, function_mapping):
                if function_name in syscalls and function_name != "print()":
                    total += len(syscalls[function_name])
                    print(function_name)
                    print(total)
                    # print("Function " + function_name + " has syscalls " + "".join(syscalls[function_name]))
    
    return total

def count_function_calls():
    global failed, python2, failed_dirs, i, function_calls, filenames, index, syscalls
    failed = 0
    python2 = 0
    function_calls = {}
    failed_dirs = pd.DataFrame()

    totals = []

    i = 0
    index = 0
    length = 1000

    with open('syscall_mapping.json') as syscall_file:
        syscalls = json.load(syscall_file)

    filenames = pd.read_pickle('python-files.pkl')
    array_index = int(sys.argv[1])
    if array_index * length > len(filenames):
        print("Index out of bounds of filename array")
        return

    print("indices: ", array_index * length, (array_index + 1) * length)
    filenames = filenames[array_index * length:(array_index + 1) * length]

    if not os.path.isdir("function_counts"):
        os.makedirs("function_counts")

    for filename, foldername in filenames:
        total = parse_file(filename, foldername)
        if total != None:
            totals.append(total)

    output_filename = os.path.join("count_syscalls", f"{array_index}-data-nop.pkl")
    with open(output_filename, 'wb') as f:
        pickle.dump(totals, f)

    # fcall_list = list(function_calls.items())
    # fcall_list.sort(key = lambda x: x[1], reverse = True)
    # over_100 = []
    # remaining = 0
    # for item, count in fcall_list:
    #     if count >= 100:
    #         over_100.append((item, count)) 
    #     else:
    #         remaining += count
    # over_100.append(("Remaining", remaining))


    # for item, count in over_100:
    #     print(f'{item}: {count}')
    
    # print('total: ' + str(total))
    # print('failed: ' + str(failed))
    # print('python2: ' + str(python2))

    # with open("function-call-log.txt", "a") as f:
    #     for item, count in over_100:
    #         f.write(f'{item}: {count}\n')

    failed_dirs.to_pickle('failed.pkl')
    failed_dirs.to_csv('failed.csv')

    # with open('function_calls.pkl', 'wb') as picklefile:
    #     pickle.dump(function_calls, picklefile)
    

if __name__ == "__main__":
    count_function_calls()
