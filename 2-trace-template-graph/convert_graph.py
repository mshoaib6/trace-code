from helpers import clean_file, is_user_defined_module, map_variables_and_remove_call_arguments, process_call_node, function_is_relevant, get_attribute_name
from split_tree import split_tree
import ast
import json
import networkx as nx
from node import Node
import os

def _http_class_from_method(method_raw):
    import re as _re
    m = _re.search(r"""['"]([A-Za-z]+)['"]""", str(method_raw))
    if m and m.group(1).upper() in ("GET", "HEAD", "OPTIONS"):
        return "read"
    return "write"


def _http_path_label(raw):
    import re as _re
    s = str(raw)
    for m in _re.finditer(r"""(['"])((?:[^'"\\]|\\.)*)\1""", s):
        inner = m.group(2)
        u = _re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://[^/]+(/.*)$", inner)
        if u:
            return u.group(1) + "*"
        if "://" in inner:
            continue
        p = _re.search(r"(/[^/\s][^\s]*)$", inner)
        if p:
            return "*" + p.group(1) + "*"
    return None


def _http_resource_label(raw):
    import re as _re
    folded = _fold_str(raw)
    if folded is None:
        return None
    folded = _re.sub(r"^\*?[a-zA-Z][a-zA-Z0-9+.-]*://[^/*]*", "", folded)
    folded = folded.strip()
    if not folded or folded.strip("*") == "":
        return None
    if not folded.startswith("*"):
        folded = "*" + folded
    if not folded.endswith("*"):
        folded = folded + "*"
    return folded


def _http_endpoint_label(raw):
    return _http_resource_label(raw)


_GENERIC_SEG = {
    "api", "v1", "v2", "v3", "admin", "login", "logout", "index", "home",
    "user", "users", "app", "apps", "web", "cgi", "rest", "public", "static",
    "cgi-bin", "servlet", "action", "do", "php", "asp", "aspx", "jsp", "html",
}


def _coarse_peer_alts(resource, url):
    import re as _re
    alts = [resource] if resource else []
    if resource:
        core = resource.strip("*")
        prefix = core.split("*", 1)[0]
        segs = [s for s in prefix.split("/") if s]
        if segs:
            first = segs[0]
            coarse = "*/" + first + "*"
            if (coarse not in alts and len(first) >= 4
                    and first.lower() not in _GENERIC_SEG):
                alts.append(coarse)
    folded = _fold_str(url) if url is not None else None
    if folded:
        m = _re.search(r"://[^/\s]*?:(\d{2,5})", folded)
        if m and m.group(1) not in ("80", "443", "8080", "8000"):
            port_alt = "*:" + m.group(1) + "*"
            if port_alt not in alts:
                alts.append(port_alt)
    return alts


def _query_body_anchor(kwargs):
    import ast as _ast
    toks = []
    for key in ("params",):
        raw = kwargs.get(key)
        if not raw:
            continue
        try:
            node = _ast.parse(str(raw), mode="eval").body
        except Exception:
            continue
        if not isinstance(node, _ast.Dict):
            continue
        for k, v in zip(node.keys, node.values):
            if not (isinstance(k, _ast.Constant) and isinstance(k.value, str)):
                continue
            name = k.value
            if isinstance(v, _ast.Constant) and isinstance(v.value, str):
                toks.append(f"{name}={v.value}")
            else:
                toks.append(f"{name}=")
    if not toks:
        return None
    return "*" + "*".join(toks) + "*"


def _path_valued_param(kwargs):
    import ast as _ast, re as _re
    for key in ("params", "data", "json"):
        raw = kwargs.get(key)
        if not raw:
            continue
        try:
            node = _ast.parse(str(raw), mode="eval").body
        except Exception:
            continue
        if not isinstance(node, _ast.Dict):
            continue
        for v in node.values:
            if isinstance(v, _ast.Constant) and isinstance(v.value, str):
                val = v.value.strip()
                if _re.fullmatch(r"/[A-Za-z0-9_.\-]+(?:/[A-Za-z0-9_.\-]*)*\??", val) and len(val) > 6:
                    return "*" + val.rstrip("?") + "*"
    return None


def _merge_query(path, query):
    if query is None:
        return path
    if path is None:
        return query
    return path.rstrip("*") + "*" + query.lstrip("*")


def _value_wildcarded(label):
    import re as _re
    changed = [False]

    def repl(m):
        v = m.group(1)
        if v and v != "*" and ("/" in v or len(v) >= 8):
            changed[0] = True
            return "=*"
        return m.group(0)

    out = _re.sub(r"=([^&*\s]+)", repl, str(label))
    return out if changed[0] else None


def _pins_a_name(rung):
    import re as _re
    for seg in str(rung).replace("\\", "/").split("/"):
        core = seg.strip("*")
        if not core or "*" in core:
            continue
        if any(ch in core for ch in "?=&"):
            continue
        if core == seg:
            return True
        m = _re.search(r"\.[A-Za-z0-9]{1,6}$", core)
        if m and len(core) > len(m.group(0)):
            return True
    return False


def _resource_rungs(rung):
    r = str(rung)
    if not r.lstrip("*").startswith("/"):
        return [r]
    if _pins_a_name(r):
        return [r]
    if r.endswith("*") and len(r) > 1:
        exact = r[:-1]
        if exact and exact[-1] not in "/\\*" and _pins_a_name(exact):
            return [exact, exact + "?*"]
    return []


def _discriminating(label):
    import re as _re
    for branch in (str(label).split("|") if "|" in str(label) else [str(label)]):
        b = branch.strip()
        if _re.fullmatch(r"\.[A-Za-z0-9]{1,6}", b.strip("*")):
            continue
        s = b.replace("(executable)", "").replace("executable", "")
        core = _re.sub(r"[*/\\\s.():|;=?&-]", "", s)
        if _re.search(r"[A-Za-z0-9]{2,}", core):
            return True
    return False


def _contentful(label):
    import re as _re
    if label is None:
        return False
    core = _re.sub(r"[*/\\\s.]", "", str(label))
    return bool(_re.search(r"[A-Za-z0-9]{2,}", core))


def _is_rooted_path(s):
    import re as _re
    s = str(s)
    return (s.startswith("/") or s.startswith("\\\\")
            or bool(_re.match(r"^[A-Za-z]:[\\/]", s)))


def _path_tolerance(label):
    s = str(label)
    if not s or "*" in s:
        return s
    if _is_rooted_path(s):
        return s + "*" if s.endswith(("/", "\\")) else s
    return "*" + s


def _operand_label(raw):
    folded = _fold_str(raw)
    if folded is None or folded.strip("*") == "":
        return None
    out = _path_tolerance(folded)
    return out if out.endswith("*") else out + "*"


def _with_basename_alt(label):
    import re as _re
    core = str(label).strip("*")
    parts = _re.split(r"[\\/]", core)
    if len(parts) < 2:
        return label
    base = parts[-1].strip()
    if not base:
        return label
    distinctive = ("." in base and len(base) >= 4) or len(base) >= 8
    if not distinctive:
        return label
    alt = "*" + base + "*"
    if alt == label or alt.strip("*") == core:
        return label
    return str(label) + " | " + alt


import re as _re_mod
_re_placeholder = _re_mod.compile(r"\{[^{}]*\}")


def _fold_str(raw):
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
            walk(n.left)
        elif (isinstance(n, _ast.Call) and isinstance(n.func, _ast.Attribute)
              and n.func.attr == "format"
              and isinstance(n.func.value, _ast.Constant)
              and isinstance(n.func.value.value, str)):
            emit(_re_placeholder.sub("*", n.func.value.value))
        else:
            emit("*")

    walk(node)
    s = "".join(parts)
    s = s.replace("\x00", "")
    return s


def _exe_name(raw):
    import re as _re, ast as _ast
    try:
        _n = _ast.parse(str(raw), mode="eval").body
        if isinstance(_n, (_ast.List, _ast.Tuple)):
            parts = []
            for el in _n.elts:
                if isinstance(el, _ast.Constant) and isinstance(el.value, str):
                    parts.append(el.value)
                else:
                    parts.append("*")
            joined = " ".join(parts).strip()
            if joined and joined.strip("* ") != "":
                raw = repr(joined)
    except Exception:
        pass
    lbl = _clean_label(raw)
    if lbl is None or str(lbl).strip() in ("", "*") or str(lbl).startswith("*"):
        folded = _fold_str(raw)
        if folded is None or folded.strip("*") == "" or folded.startswith("*"):
            return "*.(executable)"
        lbl = folded
    full = _path_tolerance(str(lbl))
    cmd = str(lbl).strip()
    m = _re.match(r'^"([^"]+)"|^(\S+)', cmd)
    first = (m.group(1) or m.group(2)) if m else None
    if first:
        base = _re.split(r"[\\/]", first)[-1].strip()
        if base and base != cmd and _re.search(r"[A-Za-z0-9]{2,}", base):
            alt = "*" + base + "*"
            if alt != full:
                return full + " | " + alt
    return full


def _file_verb(mode_arg):
    m = str(mode_arg).strip().strip("'\"").lower() if mode_arg is not None else "r"
    if any(c in m for c in ("w", "a", "x", "+")):
        return "write"
    return "read"


def _arg_at(args, i):
    return args[i] if (args and 0 <= i < len(args)) else None


_KIND_KWARGS = {
    "http": ("url",),
    "file": ("file", "name", "path"),
    "spawn": ("args", "cmd"),
    "net": ("address",),
    "generic": (),
}


_CONTAINER_LITERALS = {}


def _reset_container_literals():
    _CONTAINER_LITERALS.clear()


def _record_container_literal(name, lit, variable_mapping):
    keys = {name}
    mapped = variable_mapping.get(name)
    if mapped is not None:
        try:
            keys.add(ast.unparse(mapped))
        except Exception:
            pass
    for k in keys:
        vals = _CONTAINER_LITERALS.setdefault(k, [])
        if lit not in vals:
            vals.append(lit)


def _container_path_alts(raw):
    lits = _CONTAINER_LITERALS.get(str(raw).strip())
    if not lits:
        return None
    out = []
    for lit in lits:
        lab = _operand_label(lit)
        if lab is None:
            continue
        core = lab.strip("*")
        if ("/" not in core and "\\" not in core
                and not _re_mod.search(r"\.[A-Za-z0-9]{1,5}$", core)):
            continue
        lab = _with_basename_alt(lab)
        if lab not in out:
            out.append(lab)
    return out or None


def _resolve_operand(args, kwargs, rec, kind):
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


def _subject_node(output_graph, image):
    import re as _re
    nid = "proc_" + (_re.sub(r"[^A-Za-z0-9]+", "_", str(image)).strip("_").lower() or "subject")
    if nid not in output_graph:
        output_graph.add_node(nid, node_info=Node(nid, "Process", str(image)))
    return nid


def _attribute_assign_keys(target, function_mapping):
    keys = []
    try:
        qualified = get_attribute_name(target, function_mapping)
    except Exception:
        qualified = None
    if qualified:
        keys.append(str(qualified) + "=")
    bare = str(target.attr) + "="
    if bare not in keys:
        keys.append(bare)
    return keys


def handle_attribute_assign(target, value, function_mapping, variable_mapping,
                            output_graph, base_process_node):
    for key in _attribute_assign_keys(target, function_mapping):
        if key not in syscalls:
            continue
        try:
            operand = ast.unparse(
                map_variables_and_remove_call_arguments(value, variable_mapping))
        except Exception:
            operand = "*"
        handle_function(key, [operand], {}, output_graph, base_process_node)
        return


def _returns_to_assign(body, target):
    import copy as _copy

    class _R(ast.NodeTransformer):
        def visit_FunctionDef(self, node):
            return node

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_Lambda(self, node):
            return node

        def visit_Return(self, node):
            if node.value is None:
                return node
            return ast.copy_location(
                ast.Assign(targets=[_copy.deepcopy(target)], value=node.value), node)

    out = []
    for st in body:
        try:
            out.append(_R().visit(st))
        except Exception:
            out.append(st)
    return out


def _inline_functions(tree, max_depth=3):
    funcs = {n.name: n for n in ast.walk(tree)
             if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    classes = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)}

    def _method(cls, name):
        for m in cls.body:
            if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)) and m.name == name:
                return m
        return None

    def binds_for(fn, call):
        out = []
        names = [a.arg for a in fn.args.args]
        if names and names[0] in ("self", "cls"):
            names = names[1:]
        for i, a in enumerate(call.args):
            if i < len(names):
                out.append(ast.Assign(targets=[ast.Name(id=names[i], ctx=ast.Store())], value=a))
        for kw in call.keywords:
            if kw.arg:
                out.append(ast.Assign(targets=[ast.Name(id=kw.arg, ctx=ast.Store())], value=kw.value))
        return out

    def user_call(node):
        if not isinstance(node, ast.Call):
            return None
        f = node.func
        name = f.id if isinstance(f, ast.Name) else (f.attr if isinstance(f, ast.Attribute) else None)
        return funcs.get(name) if name in funcs else None

    inst_cls = {}

    def inline_stmts(stmts, depth):
        out = []
        for st in stmts:
            call = None
            if isinstance(st, ast.Expr) and isinstance(st.value, ast.Call):
                call = st.value
            elif isinstance(st, ast.Assign) and isinstance(st.value, ast.Call):
                call = st.value
            if (call is not None and isinstance(st, ast.Assign) and len(st.targets) == 1
                    and isinstance(st.targets[0], ast.Name)):
                cname = call.func.id if isinstance(call.func, ast.Name) else None
                cls = classes.get(cname) if cname else None
                init = _method(cls, "__init__") if cls is not None else None
                if init is not None and depth < max_depth:
                    import copy as _copy
                    out.extend(binds_for(init, call))
                    out.extend(inline_stmts([_copy.deepcopy(x) for x in init.body], depth + 1))
                    inst_cls[st.targets[0].id] = cname
                    continue
            if call is not None and isinstance(call.func, ast.Attribute) \
                    and isinstance(call.func.value, ast.Name) \
                    and call.func.value.id in inst_cls and depth < max_depth:
                cls = classes.get(inst_cls[call.func.value.id])
                m = _method(cls, call.func.attr) if cls is not None else None
                if m is not None:
                    import copy as _copy
                    body = [_copy.deepcopy(x) for x in m.body]
                    if isinstance(st, ast.Assign) and len(st.targets) == 1:
                        body = _returns_to_assign(body, st.targets[0])
                    out.extend(binds_for(m, call))
                    out.extend(inline_stmts(body, depth + 1))
                    continue
            fn = user_call(call) if call is not None else None
            if fn is not None and depth < max_depth and fn.name != getattr(fn, "_inlining", None):
                import copy as _copy
                body = [_copy.deepcopy(s) for s in fn.body]
                if isinstance(st, ast.Assign) and len(st.targets) == 1:
                    body = _returns_to_assign(body, st.targets[0])
                out.extend(binds_for(fn, call))
                out.extend(inline_stmts(body, depth + 1))
            elif isinstance(st, (ast.If, ast.For, ast.While, ast.With, ast.Try)):
                for attr in ("body", "orelse", "finalbody"):
                    if hasattr(st, attr) and getattr(st, attr):
                        setattr(st, attr, inline_stmts(getattr(st, attr), depth))
                out.append(st)
            else:
                out.append(st)
        return out

    try:
        tree.body = inline_stmts(tree.body, 0)
        ast.fix_missing_locations(tree)
    except Exception:
        pass
    return tree


def _inline_self_attrs(tree):
    assigns, counts = {}, {}

    def stringy(n):
        return (isinstance(n, ast.Constant) and isinstance(n.value, str)) \
            or isinstance(n, ast.JoinedStr) \
            or isinstance(n, ast.Name) \
            or (isinstance(n, ast.BinOp) and isinstance(n.op, (ast.Add, ast.Mod))
                and (stringy(n.left) or stringy(n.right)))

    seen_vals = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            t = node.targets[0]
            if isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name) \
                    and t.value.id == "self":
                counts[t.attr] = counts.get(t.attr, 0) + 1
                try:
                    seen_vals.setdefault(t.attr, set()).add(ast.unparse(node.value))
                except Exception:
                    seen_vals.setdefault(t.attr, set()).add(repr(node.value))
                if stringy(node.value):
                    assigns.setdefault(t.attr, node.value)
    keep = {a: v for a, v in assigns.items() if len(seen_vals.get(a, ())) == 1}
    if not keep:
        return tree

    class _Sub(ast.NodeTransformer):
        def visit_Attribute(self, node):
            self.generic_visit(node)
            if isinstance(node.ctx, ast.Load) and isinstance(node.value, ast.Name) \
                    and node.value.id == "self" and node.attr in keep:
                return keep[node.attr]
            return node

    tree = _Sub().visit(tree)
    ast.fix_missing_locations(tree)
    return tree


def handle_function(function_name, args, kwargs, output_graph, base_process_node):
    global types, syscalls, star_index, locus

    for rec in syscalls.get(function_name, []):
        kind = rec.get("kind")
        if kind == "noop":
            continue

        if kind == "http":
            url = _resolve_operand(args, kwargs, rec, "http")
            query = _query_body_anchor(kwargs)
            if locus == "remote":
                if "method_arg" in rec:
                    verb = _http_class_from_method(_arg_at(args, rec["method_arg"]) or kwargs.get("method"))
                else:
                    verb = rec.get("class", "write")
                base = _http_resource_label(url) if url is not None else None
                if base is None or not _contentful(base):
                    base = _path_valued_param(kwargs) or base
                path = _merge_query(base, query)
                if not _contentful(path):
                    path = _fresh_wildcard()
                    path_label = path
                else:
                    alts = [path]
                    if query is not None and base is not None and base != path:
                        alts.append(base)
                    core = (base or path).strip("*").split("*", 1)[0].split("?", 1)[0]
                    segs = [x for x in core.split("/") if x]
                    if len(segs) >= 2:
                        parent = "/".join(segs[:-1])
                        plast = segs[-2].lower()
                        if len(parent) >= 8 and plast not in _GENERIC_SEG:
                            palt = "*/" + parent + "/*"
                            if palt not in alts:
                                alts.append(palt)
                        first = segs[0]
                        if len(first) >= 3 and first.lower() not in _GENERIC_SEG:
                            salt = "*/" + first + "/*"
                            if salt not in alts:
                                alts.append(salt)
                    alts = [r for a in alts for r in _resource_rungs(a)]
                    alts = list(dict.fromkeys(alts))
                    if not alts:
                        path = _fresh_wildcard()
                        path_label = path
                    else:
                        path_label = " | ".join(alts)
                client_id, host_id = "net_client", "proc_host"
                if client_id not in output_graph:
                    output_graph.add_node(client_id, node_info=Node(client_id, "Socket", "*"))
                if host_id not in output_graph:
                    output_graph.add_node(host_id, node_info=Node(host_id, "Process", "*"))
                    output_graph.add_edge(client_id, host_id, syscall="access")
                output_graph.add_node(path, node_info=Node(path, "File", path_label))
                output_graph.add_edge(host_id, path, syscall=verb)
            else:
                peer = _http_endpoint_label(url) if url is not None else None
                peer = _merge_query(peer, query)
                if not _contentful(peer):
                    peer = _fresh_wildcard()
                    peer_label = peer
                else:
                    alts = _coarse_peer_alts(peer, url)
                    alts = [r for a in alts for r in _resource_rungs(a)]
                    alts = list(dict.fromkeys(alts))
                    if not alts:
                        peer = _fresh_wildcard()
                        peer_label = peer
                    else:
                        peer_label = " | ".join(alts) if len(alts) > 1 else alts[0]
                output_graph.add_node(peer, node_info=Node(peer, "Socket", peer_label))
                output_graph.add_edge(base_process_node, peer, syscall="connect")
            continue

        subject = rec.get("subject")
        acting = base_process_node if subject is None else _subject_node(output_graph, subject)

        if locus == "remote" and subject is None:
            continue

        if kind == "spawn":
            cmd = _resolve_operand(args, kwargs, rec, "spawn")
            child_label = _exe_name(cmd) if cmd is not None else "*.(executable)"
            child_id = f"child{star_index}"
            star_index += 1
            output_graph.add_node(child_id, node_info=Node(child_id, "Process", child_label))
            output_graph.add_edge(acting, child_id, syscall="create")
            continue

        if kind == "file":
            path_arg = _resolve_operand(args, kwargs, rec, "file")
            if path_arg is None:
                continue
            label = _operand_label(path_arg)
            _alts = _container_path_alts(path_arg)
            if _alts:
                label = " | ".join(_alts)
            if "mode_arg" in rec:
                verb = _file_verb(_arg_at(args, rec["mode_arg"]) or kwargs.get("mode"))
            else:
                verb = rec.get("class", "read")
            if label is None or str(label).strip() in ("", "*"):
                fid = _fresh_wildcard()
                label = fid
            else:
                fid = str(label)
                if rec.get("reg") and not str(label).startswith("*"):
                    label = "*" + str(label)
                if " | " not in str(label):
                    label = _with_basename_alt(label)
            output_graph.add_node(fid, node_info=Node(fid, "File", label))
            output_graph.add_edge(acting, fid, syscall=verb)
            continue

        if kind == "net":
            if rec.get("peer"):
                label = _net_peer_label(_resolve_operand(args, kwargs, rec, "net"))
            else:
                label = None
            if label is None or str(label).strip() in ("", "*"):
                if subject is None:
                    nid = _fresh_wildcard()
                    label = nid
                else:
                    nid = f"net_peer{star_index}"
                    star_index += 1
                    label = "*"
            else:
                nid = str(label)
            output_graph.add_node(nid, node_info=Node(nid, "Socket", label))
            cls = rec.get("class", "connect")
            if cls == "receive":
                output_graph.add_edge(nid, acting, syscall=cls)
            else:
                output_graph.add_edge(acting, nid, syscall=cls)
            continue

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
                output_graph.add_edge(target_id, acting, syscall=syscall_name)
            else:
                output_graph.add_edge(acting, target_id, syscall=syscall_name)
            continue

        
def handle_tree(tree, filename, foldername, output_graph, base_process_node):
    global types, syscalls, star_index
    function_mapping = {}
    user_defined_functions = set()
    user_defined_modules_and_functions = set()
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
    
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    variable_name = target.id
                    mapped_expression = map_variables_and_remove_call_arguments(node.value, variable_mapping)
                    variable_mapping[variable_name] = mapped_expression
                elif isinstance(target, ast.Attribute):
                    handle_attribute_assign(target, node.value, function_mapping,
                                            variable_mapping, output_graph,
                                            base_process_node)
                elif isinstance(target, ast.Subscript):
                    base = target
                    while isinstance(base, ast.Subscript):
                        base = base.value
                    if isinstance(base, ast.Name):
                        try:
                            lit = ast.unparse(
                                map_variables_and_remove_call_arguments(node.value, variable_mapping))
                        except Exception:
                            lit = None
                        if lit:
                            _record_container_literal(base.id, lit, variable_mapping)
                elif isinstance(target, ast.Tuple):
                    for element in target.elts:
                        if isinstance(element, ast.Name):
                            variable_name = element.id
                            mapped_expression = map_variables_and_remove_call_arguments(node.value, variable_mapping)
                            variable_mapping[variable_name] = mapped_expression
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
            if isinstance(node.target, ast.Attribute) and node.value is not None:
                handle_attribute_assign(node.target, node.value, function_mapping,
                                        variable_mapping, output_graph,
                                        base_process_node)
            if isinstance(node.target, ast.Name):
                variable_name = node.target.id
                type = ast.parse(ast.unparse(node.annotation) + "()").body[0].value
                variable_mapping[variable_name] = type
        elif isinstance(node, ast.With):
            for item in node.items:
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
        if isinstance(node, ast.Call):
            function_name, args, kwargs = process_call_node(node, function_mapping, variable_mapping)

            if function_is_relevant(function_name, user_defined_functions, user_defined_modules_and_functions, function_mapping):
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
    return graph_signature(graph1) == graph_signature(graph2)


_NODE_TYPE_TO_SIG = {"Process": "process", "File": "file", "Socket": "net", "None": "file"}

_SYSCALL_NORMALIZE = {
    "spawn": "create",
    "execute": "create",
    "receive": "recvfrom",
    "send": "sendto",
    "creat": "create",
}


def _sig_id(nid, seen):
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
    import re as _re
    s = str(label).strip()
    is_fstring = s.startswith(("f'", 'f"'))
    if is_fstring:
        s = s[1:]
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"'):
        inner = s[1:-1]
        if s[0] not in inner:
            if is_fstring and _re.search(r"\{[^{}]+\}", inner):
                return "*"
            try:
                import codecs
                inner = codecs.decode(inner.encode("utf-8", "ignore"), "unicode_escape")
            except Exception:
                pass
            s = inner or s
            m = _re.match(r"^(https?)://[^/]+(/.*)$", s)
            if m:
                s = m.group(2)
            return s or label
    if _re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", s):
        return "*"
    if _re.search(r"[a-zA-Z_][a-zA-Z0-9_]*\s*\(", s) or \
       _re.search(r"\b[a-zA-Z_][a-zA-Z0-9_]*\.[a-zA-Z_]", s) or \
       "{" in s or "+" in s:
        return "*"
    return s or label


def _canonical_graph_signature(graph):
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

    active = {u for u, _, _ in normalized_edges} | {v for _, v, _ in normalized_edges}
    keep = {k: v for k, v in keep.items() if k in active}

    id_map = {}
    seen = set()
    for nid, info in keep.items():
        id_map[nid] = _sig_id(info.id, seen)

    if not any(_discriminating(info.label) for info in keep.values()):
        with open(out_path, "w", encoding="utf-8") as f:
            f.write("")
        return

    lines = []
    for nid, info in keep.items():
        t = _NODE_TYPE_TO_SIG.get(info.type, "file")
        label = str(info.label).replace("\r", " ").replace("\n", " ").replace("\t", " ").strip()
        if not label:
            label = "*"
        lines.append(f"NODE {id_map[nid]} {t} {label}")
    for u, v, sc in normalized_edges:
        if u in id_map and v in id_map:
            lines.append(f"EDGE {id_map[u]} {id_map[v]} {sc}")

    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + ("\n" if lines else ""))


_MAX_TREES = 64


def _detect_locus(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = None
            f = node.func
            if isinstance(f, ast.Attribute):
                last = f.attr
                if last in ("get", "post", "put", "delete", "head", "patch", "urlopen"):
                    return "remote"
    return "local"


def _split_remote_anchors(output_graph):
    client_id, host_id = "net_client", "proc_host"
    if client_id not in output_graph or host_id not in output_graph:
        return [output_graph]
    resources = [v for _, v in output_graph.out_edges(host_id) if v != host_id]
    resources = list(dict.fromkeys(resources))
    if len(resources) <= 1:
        graphs = [output_graph]
        for res in resources:
            P = nx.MultiDiGraph()
            for nid in (host_id, res):
                P.add_node(nid, **output_graph.nodes[nid])
            for u, v, data in output_graph.edges(data=True):
                if u in P and v in P:
                    P.add_edge(u, v, **data)
            if P.number_of_edges():
                graphs.append(P)
        return graphs
    graphs = []
    for res in resources:
        H = nx.MultiDiGraph()
        for nid in (client_id, host_id, res):
            H.add_node(nid, **output_graph.nodes[nid])
        for u, v, data in output_graph.edges(data=True):
            if u in H and v in H:
                H.add_edge(u, v, **data)
        graphs.append(H)
        P = nx.MultiDiGraph()
        for nid in (host_id, res):
            P.add_node(nid, **output_graph.nodes[nid])
        for u, v, data in output_graph.edges(data=True):
            if u in P and v in P:
                P.add_edge(u, v, **data)
        if P.number_of_edges():
            graphs.append(P)
    return graphs


def _split_local_anchors(output_graph):
    extra = []
    for n, data in list(output_graph.nodes(data=True)):
        info = data.get("node_info")
        if info is None or info.type not in ("File", "Socket"):
            continue
        if output_graph.out_degree(n) > 0 or not _contentful(info.label):
            continue
        preds = [u for u, _ in output_graph.in_edges(n)]
        if not preds:
            continue
        H = nx.MultiDiGraph()
        H.add_node(n, **output_graph.nodes[n])
        for p in preds:
            H.add_node(p, **output_graph.nodes[p])
            for u, v, d in output_graph.edges(data=True):
                if u == p and v == n:
                    H.add_edge(u, v, **d)
        extra.append(H)
    return [output_graph] + extra if extra else [output_graph]


def _expand_components(parts):
    out = []
    for g in parts:
        out.append(g)
        try:
            comps = list(nx.weakly_connected_components(g))
        except Exception:
            continue
        if len(comps) <= 1:
            continue
        for nodes in comps:
            H = g.subgraph(nodes).copy()
            if H.number_of_edges():
                out.append(H)
    return out


def convert_graph(filename, foldername, out_format="txt", locus_mode="auto"):
    global types, syscalls, locus
    _reset_container_literals()
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
    process_id = "*.(executable)"
    written = 0
    seen_signatures = set()
    for idx, tree in enumerate(trees):
        output_graph = nx.MultiDiGraph()
        base_process_node = Node(process_id, 'Process', process_id)
        if locus == "local":
            output_graph.add_node(process_id, node_info=base_process_node)
        tree = _inline_functions(tree)
        tree = _inline_self_attrs(tree)
        handle_tree(tree, filename, foldername, output_graph, process_id)

        if output_graph.number_of_edges() == 0:
            continue

        if locus == "remote":
            parts = _split_remote_anchors(output_graph)
        elif locus == "local":
            parts = _split_local_anchors(output_graph)
        else:
            parts = [output_graph]
        parts = _expand_components(parts)
        for sub, g in enumerate(parts):
            if g.number_of_edges() == 0:
                continue
            sig_key = _canonical_graph_signature(g)
            if sig_key in seen_signatures:
                continue
            seen_signatures.add(sig_key)

            suffix = f"-{sub}" if len(parts) > 1 else ""
            if out_format == "txt":
                write_sig_txt(g, f'graphs/graph-{idx}{suffix}.txt')
            else:
                nx.drawing.nx_pydot.write_dot(g, f'graphs/graph-{idx}{suffix}.dot')
            written += 1
    return written

