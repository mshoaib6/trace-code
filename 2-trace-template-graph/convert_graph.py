from helpers import clean_file, is_user_defined_module, map_variables_and_remove_call_arguments, process_call_node, function_is_relevant
from split_tree import split_tree
import ast
import json
import networkx as nx
from node import Node
import os

def handle_function(function_name, args, output_graph, base_process_node):
    global syscalls, star_index
    for syscall in syscalls[function_name]:
        syscall_name = syscall['syscall']
        arg_string = syscall['args']
        if syscall_name in ("open", "openat"):
            if arg_string == "*":
                filename = f"*{star_index}"
                file_node = Node(filename, 'File', filename)
                star_index += 1
                output_graph.add_node(filename, node_info=file_node)
                output_graph.add_edge(base_process_node, filename, syscall=syscall_name)
                output_graph.add_edge(filename, base_process_node, syscall=syscall_name)
            else:
                mode = args[-1]
                filename = args[0]
                file_node = Node(filename, 'File', filename)
                # Edge convention: process -> file (the process performs the I/O).
                # Matches the shipped TRACE sig/prov graph convention.
                if "r" in mode or "t" in mode:
                    output_graph.add_node(filename, node_info=file_node)
                    output_graph.add_edge(base_process_node, filename, syscall=syscall_name)
                elif "w" in mode or "a" in mode or "x" in mode:
                    output_graph.add_node(filename, node_info=file_node)
                    output_graph.add_edge(base_process_node, filename, syscall=syscall_name)
                elif "+" in mode:
                    output_graph.add_node(filename, node_info=file_node)
                    output_graph.add_edge(base_process_node, filename, syscall=syscall_name)
        else:
            object_type, direction = types[syscall_name]
            if direction != "none":
                if arg_string == 'args':
                    if not args:
                        continue
                    arg_string = args[0]
                    object_node = Node(arg_string, object_type, arg_string)
                    output_graph.add_node(arg_string, node_info=object_node)
                    target_id = arg_string
                elif arg_string == '*':
                    filename = f"*{star_index}"
                    star_index += 1
                    object_node = Node(filename, object_type, filename)
                    output_graph.add_node(filename, node_info=object_node)
                    target_id = filename
                else:
                    object_node = Node(arg_string, object_type, arg_string)
                    output_graph.add_node(arg_string, node_info=object_node)
                    target_id = arg_string
                if direction == "in":
                    output_graph.add_edge(target_id, base_process_node, syscall=syscall_name)
                else:
                    output_graph.add_edge(base_process_node, target_id, syscall=syscall_name)

        
def handle_tree(tree, filename, foldername, output_graph, base_process_node):
    global types, syscalls, star_index
    # mapping of functions/aliases to modules and original function names
    function_mapping = {}
    # set of user defined functions within a file
    user_defined_functions = set()
    # set of modules defined by users
    user_defined_modules_and_functions = set()
    # mapping of variable names to complete statements
    variable_mapping = {}

    star_index = 0
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
            function_name, args = process_call_node(node, function_mapping, variable_mapping)
            
            # Check that function isn't user defined
            if function_is_relevant(function_name, user_defined_functions, user_defined_modules_and_functions, function_mapping):
                # handle function call
                if function_name in syscalls:
                    handle_function(function_name, args, output_graph, base_process_node)

def normalize_syscall_value(value):
    if isinstance(value, list):
        return value[0] if value else None
    if isinstance(value, str):
        return value.strip('"')
    return value


def normalize_node_id(node_id):
    if isinstance(node_id, str):
        node_id = node_id.strip('"')
        node_id = node_id.replace("\\\\", "\\")
        node_id = node_id.replace("\\\"", "\"").replace("\\'", "'")
        if (node_id.startswith('f"') or node_id.startswith("f'")) and node_id.endswith("\\"):
            node_id = node_id[:-1]
    return node_id


def iter_graph_edges(graph):
    if graph.is_multigraph():
        for u, v, key, data in graph.edges(keys=True, data=True):
            yield u, v, data
    else:
        for u, v, data in graph.edges(data=True):
            yield u, v, data


def graph_signature(graph):
    edges = []
    for u, v, data in iter_graph_edges(graph):
        u = normalize_node_id(u)
        v = normalize_node_id(v)
        syscall = normalize_syscall_value(data.get("syscall"))
        edges.append((u, v, syscall))
    edges.sort()
    nodes = sorted({u for u, _, _ in edges} | {v for _, v, _ in edges})
    return nodes, edges


def graphs_are_equal(graph1, graph2):
    """Check if two graphs are equal by node names and syscall-labeled edges."""
    return graph_signature(graph1) == graph_signature(graph2)


_NODE_TYPE_TO_SIG = {"Process": "process", "File": "file", "Socket": "net", "None": "file"}

# Normalize stage-2 syscall names onto the stage-3 alignment vocabulary.
# Stage 3 (trace-align) + our prov graphs use: create, read, write, open, close,
# access, connect, recvfrom, sendto, dns, query, rename. Keep the mapping tight
# so stage 2 output aligns cleanly without stage-3 modifications.
_SYSCALL_NORMALIZE = {
    "spawn": "create",
    "execute": "create",
    "receive": "recvfrom",
    "send": "sendto",
    "creat": "create",
}


def _sig_id(nid, seen):
    """Deterministic, stage-3-safe id: prefix by type, sanitize, uniqueify."""
    import re as _re
    base = _re.sub(r"[^A-Za-z0-9_]+", "_", str(nid))[:40].strip("_") or "v"
    out = f"sig_{base}"
    n = 2
    while out in seen:
        out = f"sig_{base}_{n}"
        n += 1
    seen.add(out)
    return out


def _clean_label(label):
    """Strip AST-unparse artefacts and collapse dynamic expressions to wildcards.

    * Bare string literals (``'/path'``)       -> ``/path``
    * Escaped Windows paths (``'C:\\\\a\\\\b'``) -> ``C:\\a\\b``
    * URLs (``http://host/p``)                 -> ``/p``
    * Dynamic expressions that we cannot resolve to a concrete string
      (``self.url + '/foo'``, ``args.target``, ``f'{x}/cli'``) -> ``*``
      so stage 3 label_matches treats them as wildcards.
    """
    import re as _re
    s = str(label).strip()
    is_fstring = s.startswith(("f'", 'f"'))
    if is_fstring:
        s = s[1:]
    # Try: is this a literal string? If yes, decode escapes.
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"'):
        inner = s[1:-1]
        if s[0] not in inner:  # no embedded quote of same kind -> clean literal
            # An f-string with `{var}` is not a literal -- wildcard it.
            if is_fstring and _re.search(r"\{[^{}]+\}", inner):
                return "*"
            try:
                import codecs
                inner = codecs.decode(inner.encode("utf-8", "ignore"), "unicode_escape")
            except Exception:
                pass
            s = inner or s
            # URL path extraction.
            m = _re.match(r"^(https?)://[^/]+(/.*)$", s)
            if m:
                s = m.group(2)
            return s or label
    # Bare identifier (variable name, no dots/slashes/quotes) -> unresolved.
    if _re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", s):
        return "*"
    # Not a literal. If it looks like an expression (method call, attribute
    # access on non-string, binary op, f-string with subs) -> wildcard.
    if _re.search(r"[a-zA-Z_][a-zA-Z0-9_]*\s*\(", s) or \
       _re.search(r"\b[a-zA-Z_][a-zA-Z0-9_]*\.[a-zA-Z_]", s) or \
       "{" in s or "+" in s:
        return "*"
    return s or label


def _canonical_graph_signature(graph):
    """Stable (nodes, edges) tuple used to dedupe across stage-2 variants."""
    nodes = []
    edges = []
    for _, data in graph.nodes(data=True):
        info = data.get("node_info")
        if info is None:
            continue
        nodes.append((info.type, _clean_label(info.label)))
    for u, v, data in graph.edges(data=True):
        nu = graph.nodes[u].get("node_info")
        nv = graph.nodes[v].get("node_info")
        if nu is None or nv is None:
            continue
        edges.append((
            _clean_label(nu.label), _clean_label(nv.label),
            str(data.get("syscall", "")),
        ))
    return tuple(sorted(nodes)), tuple(sorted(edges))


def write_sig_txt(graph, out_path):
    """Write a stage-3-compatible NODE/EDGE text file from a stage-2 template graph.

    Filters applied:
      * normalizes syscall vocabulary (spawn/execute -> create, etc.)
      * drops pure-wildcard file/net nodes with label '*' (no useful anchor)
      * prunes nodes that are left with no edges after filtering
    """
    # First, collect raw nodes/edges and drop trivial-wildcard noise ('*', '*0', ...).
    # We keep the base process '*.*' and any concrete labels.
    import re as _re
    _wildcard_rx = _re.compile(r"^\*\d*$")
    keep = {}
    for nid, data in graph.nodes(data=True):
        info = data.get("node_info")
        if info is None:
            continue
        label = _clean_label(info.label).strip()
        if info.label != "*.*" and _wildcard_rx.match(label):
            continue
        keep[nid] = info

    normalized_edges = []
    for u, v, data in graph.edges(data=True):
        if u not in keep or v not in keep:
            continue
        sc = data.get("syscall", "other")
        sc = _SYSCALL_NORMALIZE.get(sc, sc)
        normalized_edges.append((u, v, sc))

    # Drop nodes with no remaining edges (orphan wildcards after filtering).
    active = {u for u, _, _ in normalized_edges} | {v for _, v, _ in normalized_edges}
    # Keep the base process vertex even if edgeless so the graph has an anchor.
    base_id = None
    for nid, info in keep.items():
        if info.type == "Process" and info.label == "*.*":
            base_id = nid
            active.add(nid)
            break
    keep = {k: v for k, v in keep.items() if k in active}

    id_map = {}
    seen = set()
    for nid, info in keep.items():
        id_map[nid] = _sig_id(info.id, seen)

    lines = []
    for nid, info in keep.items():
        t = _NODE_TYPE_TO_SIG.get(info.type, "file")
        lines.append(f"NODE {id_map[nid]} {t} {_clean_label(info.label)}")
    for u, v, sc in normalized_edges:
        if u in id_map and v in id_map:
            lines.append(f"EDGE {id_map[u]} {id_map[v]} {sc}")

    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + ("\n" if lines else ""))


# Hard cap on path-variant enumeration so deeply branchy PoCs don't blow up.
# Real exploit PoCs rarely need more than a handful of distinct variants;
# anything beyond this is almost certainly duplicate paths that the dedupe
# step would drop anyway.
_MAX_TREES = 64


def convert_graph(filename, foldername, out_format="txt"):
    """Generate template graphs. out_format='txt' (stage-3 ready) or 'dot' (legacy pydot)."""
    global types, syscalls
    tree = clean_file(filename, foldername)
    if tree is None:
        return 0
    trees = split_tree(tree)
    if len(trees) > _MAX_TREES:
        trees = trees[:_MAX_TREES]
    with open('type_mapping.json') as type_file:
        types = json.load(type_file)
    with open('syscall_mapping.json') as syscall_file:
        syscalls = json.load(syscall_file)

    os.makedirs('graphs', exist_ok=True)
    process_id = "*.*"
    written = 0
    seen_signatures = set()  # in-run dedupe across variants
    for idx, tree in enumerate(trees):
        output_graph = nx.DiGraph()
        base_process_node = Node(process_id, 'Process', process_id)
        output_graph.add_node(process_id, node_info=base_process_node)
        handle_tree(tree, filename, foldername, output_graph, process_id)

        # Skip graphs that carry no syscall edges (pure control-flow stubs).
        if output_graph.number_of_edges() == 0:
            continue

        # In-run dedupe by canonical signature (labels + syscall-labeled edges).
        sig_key = _canonical_graph_signature(output_graph)
        if sig_key in seen_signatures:
            continue
        seen_signatures.add(sig_key)

        if out_format == "txt":
            write_sig_txt(output_graph, f'graphs/graph-{idx}.txt')
        else:
            nx.drawing.nx_pydot.write_dot(output_graph, f'graphs/graph-{idx}.dot')
        written += 1
    return written
# def main():
#     convert_graph("examples/follina.py", "examples")

# if __name__ == "__main__":
#     main()
