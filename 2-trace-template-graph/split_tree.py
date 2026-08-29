import ast
import copy

class NodeReplace(ast.NodeTransformer):
    def __init__(self, old_node, new_node):
        self.old_node = old_node
        self.new_node = new_node

    def generic_visit(self, node):
        if node == self.old_node:
            return self.new_node
        return ast.NodeTransformer.generic_visit(self, node)

def replace_node(tree, old_node, new_node):
    return NodeReplace(old_node, new_node).visit(tree)

def map_corresponding_nodes(original_node, copied_node, mapping):
    mapping[original_node] = copied_node

    for original_child, copied_child in zip(ast.iter_child_nodes(original_node), ast.iter_child_nodes(copied_node)):
        map_corresponding_nodes(original_child, copied_child, mapping)

def copy_tree(tree, old_mapping):
    inv_map = {v: k for k, v in old_mapping.items()}
    tree_1 = copy.deepcopy(tree)
    tree_2 = copy.deepcopy(tree)
    mapping_1_temp = {}
    mapping_1 = {}
    map_corresponding_nodes(tree, tree_1, mapping_1_temp)
    for key in mapping_1_temp:
        if key in inv_map:
            original_tree_node = inv_map[key]
            mapping_1[original_tree_node] = mapping_1_temp[key]
    mapping_2_temp = {}
    mapping_2 = {}
    map_corresponding_nodes(tree, tree_2, mapping_2_temp)
    for key in mapping_2_temp:
        if key in inv_map:
            original_tree_node = inv_map[key]
            mapping_2[original_tree_node] = mapping_2_temp[key]
    return tree_1, mapping_1, tree_2, mapping_2

class TreeSplitter(ast.NodeVisitor):
    def __init__(self, original_ast):
        self.trees = [original_ast]
        mapping = {}
        map_corresponding_nodes(original_ast, original_ast, mapping)
        self.mappings = [mapping]

    def visit_If(self, node):
        new_trees = []
        new_mappings = []
        for tree, mapping in zip(self.trees, self.mappings):
            if node in mapping:
                tree_if, mapping_if, tree_else, mapping_else = copy_tree(tree, mapping)
                if node in mapping_if:
                    if_mapped_node = mapping_if[node]
                    if_mapped_node.body.insert(0, ast.Expr(value=if_mapped_node.test))
                    tree_if = replace_node(tree_if, if_mapped_node, if_mapped_node.body)
                    new_trees.append(tree_if)
                    new_mappings.append(mapping_if)
                    else_mapped_node = mapping_else[node]
                    else_mapped_node.orelse.insert(0, ast.Expr(else_mapped_node.test))
                    tree_else = replace_node(tree_else, else_mapped_node, else_mapped_node.orelse)
                    new_trees.append(tree_else)
                    new_mappings.append(mapping_else)
                else:
                    new_trees.append(tree)
                    new_mappings.append(mapping)
            else:
                new_trees.append(tree)
                new_mappings.append(mapping)


        self.trees = new_trees
        self.mappings = new_mappings

        for child_node in ast.iter_child_nodes(node):
            self.visit(child_node)

    def visit_While(self, node):
        new_trees = []
        new_mappings = []
        for tree, mapping in zip(self.trees, self.mappings):
            if node in mapping:
                tree_body_visited, mapping_body_visited, tree_body_skipped, mapping_body_skipped = copy_tree(tree, mapping)
                if node in mapping_body_visited:
                    visited_mapped_node = mapping_body_visited[node]
                    visited_mapped_node.body.insert(0, ast.Expr(value=visited_mapped_node.test))
                    tree_body_visited = replace_node(tree_body_visited, visited_mapped_node, visited_mapped_node.body)
                    new_trees.append(tree_body_visited)
                    new_mappings.append(mapping_body_visited)
                    skipped_mapped_node = mapping_body_skipped[node]
                    tree_body_skipped = replace_node(tree_body_skipped, skipped_mapped_node, ast.Expr(value=visited_mapped_node.test))
                    new_trees.append(tree_body_skipped)
                    new_mappings.append(mapping_body_skipped)
                else:
                    new_trees.append(tree)
                    new_mappings.append(mapping)
            else:
                new_trees.append(tree)
                new_mappings.append(mapping)


        self.trees = new_trees
        self.mappings = new_mappings

        for child_node in ast.iter_child_nodes(node):
            self.visit(child_node)

    def visit_For(self, node):
        new_trees = []
        new_mappings = []
        for tree, mapping in zip(self.trees, self.mappings):
            if node in mapping:
                tree_for, mapping_for, tree_else, mapping_else = copy_tree(tree, mapping)
                tree_for_else, mapping_for_else, _, _ = copy_tree(tree, mapping)
                if node in mapping_for:
                    for_mapped_node = mapping_for[node]
                    for_mapped_node.body.insert(0, ast.Expr(value=for_mapped_node.iter))
                    tree_for = replace_node(tree_for, for_mapped_node, for_mapped_node.body)
                    new_trees.append(tree_for)
                    new_mappings.append(mapping_for)

                    else_mapped_node = mapping_else[node]
                    else_mapped_node.orelse.insert(0, ast.Expr(value=else_mapped_node.iter))
                    tree_else = replace_node(tree_else, else_mapped_node, else_mapped_node.orelse)
                    new_trees.append(tree_else)
                    new_mappings.append(mapping_else)

                    for_else_mapped_node = mapping_for_else[node]
                    for_else_mapped_node.body += for_else_mapped_node.orelse
                    for_else_mapped_node.body.insert(0, ast.Expr(value=for_else_mapped_node.iter))
                    tree_for_else = replace_node(tree_for_else, for_else_mapped_node, for_else_mapped_node.body)
                    new_trees.append(tree_for_else)
                    new_mappings.append(mapping_for_else)
                else:
                    new_trees.append(tree)
                    new_mappings.append(mapping)
            else:
                new_trees.append(tree)
                new_mappings.append(mapping)


        self.trees = new_trees
        self.mappings = new_mappings

        for child_node in ast.iter_child_nodes(node):
            self.visit(child_node)

    def visit_IfExp(self, node):
        new_trees = []
        new_mappings = []
        for tree, mapping in zip(self.trees, self.mappings):
            if node in mapping:
                tree_if, mapping_if, tree_else, mapping_else = copy_tree(tree, mapping)
                if node in mapping_if:
                    if_mapped_node = mapping_if[node]
                    tree_if.body.append(ast.Expr(if_mapped_node.test))
                    tree_if = replace_node(tree_if, if_mapped_node, if_mapped_node.body)
                    new_trees.append(tree_if)
                    new_mappings.append(mapping_if)
                    else_mapped_node = mapping_else[node]
                    tree_else.body.append(ast.Expr(else_mapped_node.test))
                    tree_else = replace_node(tree_else, else_mapped_node, else_mapped_node.orelse)
                    new_trees.append(tree_else)
                    new_mappings.append(mapping_else)
                else:
                    new_trees.append(tree)
                    new_mappings.append(mapping)
            else:
                new_trees.append(tree)
                new_mappings.append(mapping)


        self.trees = new_trees
        self.mappings = new_mappings

        for child_node in ast.iter_child_nodes(node):
            self.visit(child_node)

    def visit_Try(self, node):
        new_trees = []
        new_mappings = []
        for tree, mapping in zip(self.trees, self.mappings):
            if node in mapping:
                tree_try, mapping_try, tree_try_except, mapping_try_except = copy_tree(tree, mapping)
                if node in mapping_try:
                    try_mapped_node = mapping_try[node]
                    try_mapped_node.body += try_mapped_node.orelse
                    try_mapped_node.body += try_mapped_node.finalbody
                    tree_try = replace_node(tree_try, try_mapped_node, try_mapped_node.body)
                    new_trees.append(tree_try)
                    new_mappings.append(mapping_try)
                    try_except_mapped_node = mapping_try_except[node]
                    for index in range(len(try_except_mapped_node.handlers)):
                        tree_handler, mapping_handler, _, _ = copy_tree(tree, mapping)
                        tree_handler_mapped_node = mapping_handler[node]
                        tree_handler_mapped_node.handlers = tree_handler_mapped_node.body + [tree_handler_mapped_node.handlers[index].body]
                        tree_handler_mapped_node.handlers += tree_handler_mapped_node.finalbody
                        tree_handler = replace_node(tree_handler, tree_handler_mapped_node, tree_handler_mapped_node.handlers)
                        new_trees.append(tree_handler)
                        new_mappings.append(mapping_handler)
                else:
                    new_trees.append(tree)
                    new_mappings.append(mapping)
            else:
                new_trees.append(tree)
                new_mappings.append(mapping)


        self.trees = new_trees
        self.mappings = new_mappings

        for child_node in ast.iter_child_nodes(node):
            self.visit(child_node)

def cleanup_trees(trees):
    unique_trees = []
    unique_unparses = set()
    for tree in trees:
        unparse = ast.unparse(tree)
        if unparse not in unique_unparses:
            unique_unparses.add(unparse)
            unique_trees.append(tree)
    return unique_trees

_SPLIT_BUDGET = 256


def split_tree(tree):
    splitter = TreeSplitter(tree)
    orig_visit = splitter.visit

    def _bounded_visit(node):
        if len(splitter.trees) >= _SPLIT_BUDGET:
            return
        return orig_visit(node)

    splitter.visit = _bounded_visit
    splitter.visit(tree)
    return cleanup_trees(splitter.trees)
