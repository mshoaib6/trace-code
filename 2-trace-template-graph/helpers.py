import os
import ast
import lib2to3
from lib2to3 import refactor
import ast
import autopep8
import builtins
import copy

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
    
    if function_name:
        function_name += "()"

    args = []
    for arg in node.args:
        try:
            args.append(ast.unparse(arg))
        except ValueError:
            args.append("*")
    kwargs = {}
    for kw in node.keywords:
        if kw.arg is None:
            continue
        try:
            kwargs[kw.arg] = ast.unparse(kw.value)
        except ValueError:
            kwargs[kw.arg] = "*"
    return function_name, args, kwargs

def is_user_defined_module(foldername, module_name):
    foldername = os.path.join('total-folder', foldername)
    module_name = '/'.join(module_name.split('.'))
    file_path = os.path.join(foldername, module_name + ".py")
    return os.path.exists(file_path)

def function_is_relevant(function_name, user_defined_functions, user_defined_modules_and_functions, function_mapping):
    if not function_name:
        return False
    if function_name in user_defined_functions:
        return False
    if function_name in builtins.__dict__.keys():
        return True
    if "." in function_name:
        for module in user_defined_modules_and_functions:
            if function_name.startswith(module) and (function_name == module or (len(function_name) > len(module) and function_name[len(module)] == '.')):
                return False
    return True
    
class NodeReplacer(ast.NodeTransformer):
    def __init__(self, variable_mapping):
        self.variable_mapping = variable_mapping

    def visit(self, node):
        if isinstance(node, ast.Name) and node.id in self.variable_mapping:
            return self.variable_mapping[node.id]
        return self.generic_visit(node)

def map_variables_and_remove_call_arguments(value, variable_mapping):
    value = copy.deepcopy(value)
    replacer = NodeReplacer(variable_mapping=variable_mapping)
    value = replacer.visit(value)
    return value

def clean_file(filename, foldername):
    print(filename)
    try:
        try:
            with open(filename, 'r') as file:
                data = file.read()
        except UnicodeDecodeError:
            with open(filename, 'rb') as file:
                data = file.read().decode('utf-8')
    except UnicodeDecodeError: 
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
    except TabError:
        normalized_code = autopep8.fix_code(data)
        tree = ast.parse(normalized_code)
    except (lib2to3.pgen2.parse.ParseError, lib2to3.pgen2.tokenize.TokenError, IndentationError, SyntaxError) as error:
        return

    return tree
