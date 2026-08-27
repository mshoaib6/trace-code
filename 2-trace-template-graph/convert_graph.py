from helpers import clean_file, is_user_defined_module, map_variables_and_remove_call_arguments, process_call_node, function_is_relevant
from split_tree import split_tree
import ast
import json
import networkx as nx
from node import Node
import os

def _http_class_from_method(method_raw):
    """read/write from an explicit HTTP method literal (default write)."""
    import re as _re
    m = _re.search(r"""['"]([A-Za-z]+)['"]""", str(method_raw))
    if m and m.group(1).upper() in ("GET", "HEAD", "OPTIONS"):
        return "read"
    return "write"


def _http_path_label(raw):
    """Extract the target path+query from an HTTP call's first argument.

    ``raw`` is the ast-unparsed argument, e.g. ``base_url + '/a/b?x=0'`` or
    ``'http://host/a/b'``. We recover the first string literal beginning with a
    slash: that is the path the target's own log records.

    Wildcards are added only where the source says the value is uncertain, so
    each one is derived from the PoC rather than chosen per CVE:

    * trailing ``*`` always -- a target logs the query string and any suffix the
      PoC appends at run time, which the literal does not fix.
    * leading ``*`` only when the URL is built on a *variable* base
      (``base_url + '/a/b'``). Then the application's mount prefix is unknown to
      the PoC, and the target may record ``/wiki/a/b`` or ``/..;/a/b``. A URL
      written as one complete literal fixes the whole path, so it gets none.

    Returns None if no path literal exists.
    """
    import re as _re
    s = str(raw)
    # Scan the string literals in the expression; the request path lives in one.
    for m in _re.finditer(r"""(['"])((?:[^'"\\]|\\.)*)\1""", s):
        inner = m.group(2)
        # A complete URL ("http://host/path?q"): the literal fixes the whole
        # path, so no leading prefix is missing.
        u = _re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://[^/]+(/.*)$", inner)
        if u:
            return u.group(1) + "*"
        # A URL literal with no path ("http://h") carries no resource; skip it.
        if "://" in inner:
            continue
        # A path appearing in the literal ("/path", or "{base}/path" in an
        # f-string): the mount prefix is unknown, so tolerate both ends. Require
        # a single leading slash so a stray "//" is not read as a path.
        p = _re.search(r"(/[^/\s][^\s]*)$", inner)
        if p:
            return "*" + p.group(1) + "*"
    return None


def _is_rooted_path(s):
    """True when the literal fixes the whole path, so no prefix is missing."""
    import re as _re
    s = str(s)
    return (s.startswith("/") or s.startswith("\\\\")
            or bool(_re.match(r"^[A-Za-z]:[\\/]", s)))


def _path_tolerance(label):
    """Add a leading wildcard where the PoC does not fix the containing path.

    A PoC that names a bare ``human2.aspx`` or ``CompleteFTPManager.exe`` does
    not say which directory it lives in, while the target's log records the
    absolute path (``C:\\MOVEitTransfer\\wwwroot\\human2.aspx``). The missing
    prefix is a fact about the source, so the wildcard is derived, not chosen
    per CVE. A literal that is already rooted, or already carries a wildcard,
    is left exactly as written.
    """
    s = str(label)
    if not s or "*" in s:
        return s
    if _is_rooted_path(s):
        # A rooted path ending in a separator names a directory, not the file
        # the operation lands on, so the tail is still open.
        return s + "*" if s.endswith(("/", "\\")) else s
    return "*" + s


def _operand_label(raw):
    """Label for a file/object operand, or None when nothing is resolvable.

    Value propagation may leave an expression rather than a literal. Rather
    than discard the whole operand, keep the part the PoC does fix and mark the
    rest open: ``'/etc/password/' + name`` fixes the directory, so the template
    keeps ``/etc/password/*`` instead of an anonymous wildcard that anchors
    nothing. This follows the paper's rule that resolved values label vertices
    and unresolved ones become wildcards -- applied per field, not per operand.
    """
    folded = _fold_str(raw)
    if folded is None or folded.strip("*") == "":
        return None
    out = _path_tolerance(folded)
    return out if out.endswith("*") else out + "*"


def _fold_str(raw):
    r"""Fold a string-valued expression into a partially-concrete label.

    Value propagation resolves what the PoC fixes and wildcards the rest, per
    field (paper Sec 4.3). Re-parsing the (already value-substituted) expression
    lets the AST decode escapes for us -- ``'\\App_Extensions\\'`` becomes the
    value ``\App_Extensions\`` -- and lets us keep every concrete piece of a
    concatenation while marking each unresolved operand ``*``:

        share + '\\' + 'mimispool.dll'   ->   *\mimispool.dll
        install + '\\App_Extensions\\' + name + '.aspx'  ->  *\App_Extensions\*.aspx

    A single ``*`` (nothing resolvable) returns "" so the caller drops it to an
    anonymous operand rather than an anchor that matches every path. Returns
    None if the expression will not parse.
    """
    import ast as _ast
    try:
        node = _ast.parse(str(raw), mode="eval").body
    except Exception:
        return None

    parts = []

    def emit(tok):
        if tok == "*" and parts and parts[-1] == "*":
            return
        parts.append(tok)

    def walk(n):
        if isinstance(n, _ast.BinOp) and isinstance(n.op, _ast.Add):
            walk(n.left)
            walk(n.right)
        elif isinstance(n, _ast.Constant) and isinstance(n.value, str):
            emit(n.value)
        elif isinstance(n, _ast.JoinedStr):
            for v in n.values:
                if isinstance(v, _ast.Constant) and isinstance(v.value, str):
                    emit(v.value)
                else:
                    emit("*")
        elif isinstance(n, _ast.BinOp) and isinstance(n.op, _ast.Mod):
            walk(n.left)  # "%s/foo" % x keeps the format string's literal
        else:
            emit("*")

    walk(node)
    s = "".join(parts)
    # Strip a scheme+host if a full URL slipped through (paths only).
    return s


def _exe_name(raw):
    """Concrete executable label for a spawned child, or wildcard if dynamic."""
    lbl = _clean_label(raw)
    if lbl is None or str(lbl).strip() in ("", "*") or str(lbl).startswith("*"):
        return "*.(executable)"
    return _path_tolerance(str(lbl))


def _file_verb(mode_arg):
    """read/write from an open() mode argument (default read)."""
    m = str(mode_arg).strip().strip("'\"").lower() if mode_arg is not None else "r"
    if any(c in m for c in ("w", "a", "x", "+")):
        return "write"
    return "read"


def _arg_at(args, i):
    return args[i] if (args and 0 <= i < len(args)) else None


# Conventional keyword names carrying the operand for each kind, so a call
# written requests.get(url=...) or open(file=...) resolves like the positional
# form. The map may also name one explicitly via a record's "kwarg" field.
_KIND_KWARGS = {
    "http": ("url",),
    "file": ("file", "name", "path"),
    "spawn": ("args", "cmd"),
    "net": ("address",),
    "generic": (),
}


def _resolve_operand(args, kwargs, rec, kind):
    """The operand for this record, from the positional slot or a keyword.

    Real PoCs pass the observable value either positionally or by keyword; we
    try the record's positional index first, then an explicit ``kwarg`` name,
    then the conventional keyword names for the kind.
    """
    i = rec.get("arg")
    if i is not None:
        v = _arg_at(args, i)
        if v is not None:
            return v
    names = []
    if "kwarg" in rec:
        names.append(rec["kwarg"])
    names.extend(_KIND_KWARGS.get(kind, ()))
    for n in names:
        if n in kwargs:
            return kwargs[n]
    return None


def _net_peer_label(raw):
    """Peer endpoint label from a socket address argument.

    ``connect((host, port))`` and ``sendto(data, (host, port))`` carry the peer
    as an ``(host, port)`` tuple. Resolve each component the value propagation
    fixed: a literal host/port becomes ``host:port``; an unresolved host is a
    wildcard. Returns None when nothing resolvable is present.
    """
    import re as _re
    s = str(raw).strip()
    m = _re.match(r"^\(\s*(.+?)\s*,\s*(.+?)\s*\)$", s)
    if m:
        host = _clean_label(m.group(1))
        port = m.group(2).strip().strip("'\"")
        host = "*" if (host is None or str(host).strip() in ("", "*")) else str(host)
        if _re.fullmatch(r"\d+", port):
            return f"{host}:{port}"
        return host if host != "*" else None
    lbl = _clean_label(raw)
    if lbl is None or str(lbl).strip() in ("", "*"):
        return None
    return str(lbl)


def _fresh_wildcard():
    global star_index
    w = f"*{star_index}"
    star_index += 1
    return w


def handle_function(function_name, args, kwargs, output_graph, base_process_node):
    """Lower one call into template operations, driven by Pi's operation records.

    Each record's 'kind' selects the lowering; the map, not this code, holds
    which APIs are requests, spawns, file I/O, socket exchanges or generic
    object operations. Runner-side operations of a remote PoC are discarded by
    R*, so under remote locus only 'http' records survive.
    """
    global types, syscalls, star_index, locus

    for rec in syscalls.get(function_name, []):
        kind = rec.get("kind")
        if kind == "noop":
            continue

        # --- Remote target-view (R*): the request the monitored host records. ---
        if kind == "http":
            if locus != "remote":
                continue  # a local PoC's delivery is handled elsewhere; skip here
            if "method_arg" in rec:
                verb = _http_class_from_method(_arg_at(args, rec["method_arg"]) or kwargs.get("method"))
            else:
                verb = rec.get("class", "write")
            url = _resolve_operand(args, kwargs, rec, "http")
            path = _http_path_label(url) if url is not None else None
            if path is None:
                path = _fresh_wildcard()
            client_id, host_id = "net_client", "proc_host"
            if client_id not in output_graph:
                output_graph.add_node(client_id, node_info=Node(client_id, "Socket", "*"))
            if host_id not in output_graph:
                output_graph.add_node(host_id, node_info=Node(host_id, "Process", "*"))
                output_graph.add_edge(client_id, host_id, syscall="access")
            output_graph.add_node(path, node_info=Node(path, "File", path))
            output_graph.add_edge(host_id, path, syscall=verb)
            continue

        # Everything below is runner/asset-side: only for a local-locus PoC.
        if locus == "remote":
            continue

        # --- Process creation: spawn a child under the acting subject. ---
        if kind == "spawn":
            cmd = _resolve_operand(args, kwargs, rec, "spawn")
            child_label = _exe_name(cmd) if cmd is not None else "*.(executable)"
            child_id = f"child{star_index}"
            star_index += 1
            output_graph.add_node(child_id, node_info=Node(child_id, "Process", child_label))
            output_graph.add_edge(base_process_node, child_id, syscall="create")
            continue

        # --- File I/O on the running host: one edge, read or write. ---
        if kind == "file":
            path_arg = _resolve_operand(args, kwargs, rec, "file")
            if path_arg is None:
                continue
            label = _operand_label(path_arg)
            if "mode_arg" in rec:
                verb = _file_verb(_arg_at(args, rec["mode_arg"]) or kwargs.get("mode"))
            else:
                verb = rec.get("class", "read")
            if label is None or str(label).strip() in ("", "*"):
                fid = _fresh_wildcard()
                label = fid
            else:
                fid = str(label)
            output_graph.add_node(fid, node_info=Node(fid, "File", label))
            output_graph.add_edge(base_process_node, fid, syscall=verb)
            continue

        # --- Socket exchange: connect/send/receive to a network peer. ---
        if kind == "net":
            # Only address-bearing calls (connect, sendto) name the peer; send,
            # recv and file transfers act on the already-established connection,
            # so their operand is payload, never an endpoint. Labelling a peer
            # with payload bytes would invent an endpoint the target never saw.
            if rec.get("peer"):
                label = _net_peer_label(_resolve_operand(args, kwargs, rec, "net"))
            else:
                label = None
            if label is None or str(label).strip() in ("", "*"):
                nid = _fresh_wildcard()
                label = nid
            else:
                nid = str(label)
            output_graph.add_node(nid, node_info=Node(nid, "Socket", label))
            cls = rec.get("class", "connect")
            if cls == "receive":
                output_graph.add_edge(nid, base_process_node, syscall=cls)
            else:
                output_graph.add_edge(base_process_node, nid, syscall=cls)
            continue

        # --- Generic object operation via the type map (chmod/rename/...). ---
        if kind == "generic":
            syscall_name = rec.get("syscall")
            if syscall_name not in types:
                continue
            object_type, direction = types[syscall_name]
            if direction == "none":
                continue
            operand = _resolve_operand(args, kwargs, rec, "generic")
            label = _operand_label(operand) if operand is not None else None
            if label is None or str(label).strip() in ("", "*"):
                target_id = _fresh_wildcard()
                label = target_id
            else:
                target_id = str(label)
            output_graph.add_node(target_id, node_info=Node(target_id, object_type, label))
            if direction == "in":
                output_graph.add_edge(target_id, base_process_node, syscall=syscall_name)
            else:
                output_graph.add_edge(base_process_node, target_id, syscall=syscall_name)
            continue

        
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
            function_name, args, kwargs = process_call_node(node, function_mapping, variable_mapping)

            # Check that function isn't user defined
            if function_is_relevant(function_name, user_defined_functions, user_defined_modules_and_functions, function_mapping):
                # handle function call
                if function_name in syscalls:
                    handle_function(function_name, args, kwargs, output_graph, base_process_node)

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
        nodes.append((info.type, str(info.label)))
    for u, v, data in graph.edges(data=True):
        nu = graph.nodes[u].get("node_info")
        nv = graph.nodes[v].get("node_info")
        if nu is None or nv is None:
            continue
        edges.append((
            str(nu.label), str(nv.label),
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
    # Drop only *anonymous operands*: call sites whose operand the reader could
    # not resolve. Per the paper these simply do not become operations, so the
    # template shrinks. They are exactly the nodes whose id has the '*N' form
    # minted above. Structural wildcards the target view needs -- the remote
    # client/host pair and the '*.(executable)' runner -- carry real ids and
    # survive, since a wildcard still constrains structure.
    import re as _re
    _anon_id_rx = _re.compile(r"^\*\d*$")
    keep = {}
    for nid, data in graph.nodes(data=True):
        info = data.get("node_info")
        if info is None:
            continue
        if _anon_id_rx.match(str(nid)):
            continue
        keep[nid] = info

    normalized_edges = []
    seen_edges = set()
    for u, v, data in graph.edges(data=True):
        if u not in keep or v not in keep:
            continue
        sc = data.get("syscall", "other")
        sc = _SYSCALL_NORMALIZE.get(sc, sc)
        if (u, v, sc) in seen_edges:
            continue
        seen_edges.add((u, v, sc))
        normalized_edges.append((u, v, sc))

    # Drop nodes with no remaining edges (orphans after filtering).
    active = {u for u, _, _ in normalized_edges} | {v for _, v, _ in normalized_edges}
    keep = {k: v for k, v in keep.items() if k in active}

    id_map = {}
    seen = set()
    for nid, info in keep.items():
        id_map[nid] = _sig_id(info.id, seen)

    lines = []
    for nid, info in keep.items():
        t = _NODE_TYPE_TO_SIG.get(info.type, "file")
        lines.append(f"NODE {id_map[nid]} {t} {info.label}")
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


def _detect_locus(tree):
    """Infer invocation locus (paper's manifest) when not given explicitly.

    A PoC whose observable behavior is an HTTP request to a target is
    remote-locus (only the request transfers to the asset view); one that
    operates on the running host (file/process) is local-locus.
    """
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = None
            f = node.func
            if isinstance(f, ast.Attribute):
                last = f.attr
                if last in ("get", "post", "put", "delete", "head", "patch", "urlopen"):
                    return "remote"
    return "local"


def convert_graph(filename, foldername, out_format="txt", locus_mode="auto"):
    """Generate template graphs. out_format='txt' (stage-3 ready) or 'dot' (legacy pydot).

    locus_mode: 'local', 'remote', or 'auto' (infer per the paper's manifest).
    """
    global types, syscalls, locus
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

    locus = locus_mode if locus_mode in ("local", "remote") else _detect_locus(tree)

    os.makedirs('graphs', exist_ok=True)
    # Local locus anchors on the runner process; remote locus mints a target
    # host inside handle_function and leaves the runner out of the template.
    process_id = "*.(executable)"
    written = 0
    seen_signatures = set()  # in-run dedupe across variants
    for idx, tree in enumerate(trees):
        output_graph = nx.MultiDiGraph()
        base_process_node = Node(process_id, 'Process', process_id)
        if locus == "local":
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
