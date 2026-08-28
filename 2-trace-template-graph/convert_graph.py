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


def _http_resource_label(raw):
    r"""Label for the request a URL expression denotes.

    Folds the expression (so a URL assembled from literals and variables keeps
    each concrete run and wildcards the rest -- ``base + '?command=zip' + p +
    'INCLUDE'`` -> ``*command=zip*INCLUDE*``), decodes escapes, and strips a
    leading ``scheme://host`` so only the path+query the target records remains.
    A query-only anchor (``PHPRC=``) is kept even without a leading slash, since
    collectors log the whole request line. Returns None if nothing is fixed.
    """
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
    """Peer label for a local-locus request (delivery): the URL's distinctive
    path/query, which occurs in the endpoint the trace records."""
    return _http_resource_label(raw)


# Path segments too generic to serve as a coarse endpoint anchor on their own:
# an attacker-host graph names the peer by the service, not a common route word.
_GENERIC_SEG = {
    "api", "v1", "v2", "v3", "admin", "login", "logout", "index", "home",
    "user", "users", "app", "apps", "web", "cgi", "rest", "public", "static",
    "cgi-bin", "servlet", "action", "do", "php", "asp", "aspx", "jsp", "html",
}


def _coarse_peer_alts(resource, url):
    r"""Alternative endpoint labels an attacker-host graph may have recorded.

    A local-locus request logs on the runner as an outbound *connection*, and
    such a graph names the peer by the reachable endpoint -- which may be the
    full request path (``/bonita/API/pageUpload``), just the distinctive service
    prefix (``/bonita``, as ``http://host:8080/bonita``), or the ``host:port``
    when a service port is distinctive (``127.0.0.1:9200``). The exact form is a
    collector convention the PoC does not fix, so the peer label offers each as
    a ``|`` alternative (which only loosens this one node; structure still binds).
    Returns a list beginning with the full resource label.
    """
    import re as _re
    alts = [resource] if resource else []
    if resource:
        core = resource.strip("*")
        prefix = core.split("*", 1)[0]              # literal path before any query merge
        segs = [s for s in prefix.split("/") if s]
        if segs:
            first = segs[0]
            coarse = "*/" + first + "*"
            if (coarse not in alts and len(first) >= 4
                    and first.lower() not in _GENERIC_SEG):
                alts.append(coarse)
    folded = _fold_str(url) if url is not None else None
    if folded:
        # Explicit service port, even when the host folded to a wildcard
        # (http://*:9200/...): the port itself is the distinctive anchor.
        m = _re.search(r"://[^/\s]*?:(\d{2,5})", folded)
        if m and m.group(1) not in ("80", "443", "8080", "8000"):
            port_alt = "*:" + m.group(1) + "*"
            if port_alt not in alts:
                alts.append(port_alt)
    return alts


def _query_body_anchor(kwargs):
    r"""Concrete QUERY parameters a request carries, as ``name=value`` tokens
    joined by wildcards.

    Only ``params=`` is used: it becomes the URL query string, which the
    request-line a network/access-log collector records contains
    (``requests.get(u, params={'rest_route': '/pmpro/v1/order'})`` is logged as
    ``?rest_route=/pmpro/v1/order``). ``data=``/``json=`` ride in the request
    BODY, which those collectors do not log, so appending them would make the
    resource label stricter than the trace (e.g. F5's command lives in the JSON
    body, absent from the recorded ``/mgmt/tm/util/bash`` path). Each concrete
    string value is kept; a non-literal (payload variable) becomes ``name=*``.
    Returns a ``*a=x*b=y*`` fragment, or None if nothing concrete is present.
    """
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


def _merge_query(path, query):
    """Append a query/body anchor fragment to a resource/endpoint label."""
    if query is None:
        return path
    if path is None:
        return query
    return path.rstrip("*") + "*" + query.lstrip("*")


def _value_wildcarded(label):
    r"""A twin of a resource label with volatile query VALUES wildcarded.

    A parameter's name is the discriminator; its value may be a per-exploit
    artifact the trace records differently (``PHPRC=/dev/fd/0`` in the PoC vs
    ``PHPRC=/var/tmp/evilfileof.ini`` in the log). Wildcard a value that looks
    volatile -- a path (contains ``/``) or a long token -- while keeping a short
    fixed token (``setupComplete=0``) that is itself discriminating. Returns the
    wildcarded label, or None if nothing changed.
    """
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


def _discriminating(label):
    r"""True if a label names something concrete enough to anchor a detection.

    Stricter than _contentful: the structural process placeholders ``*``,
    ``*.(executable)`` and ``*.*`` carry no discriminator (every host runs
    processes), so a template built only from them matches anything. A real
    process name (``winword.exe``, ``rar.exe``), file, or endpoint token counts.
    """
    import re as _re
    s = str(label).replace("(executable)", "").replace("executable", "")
    core = _re.sub(r"[*/\\\s.():|;=?&-]", "", s)
    return bool(_re.search(r"[A-Za-z0-9]{2,}", core))


def _contentful(label):
    r"""True if a label carries a concrete discriminator, not just wildcards.

    A URL the reader could only abstract to ``*/*`` (its path built from an
    unresolved variable) names no particular resource: it matches every recorded
    request, so as an anchor it is a universal false-positive. Such a label is
    treated as an anonymous operand -- structure without a discriminator -- and
    per the paper does not become an anchored operation. Contentful means at
    least one alphanumeric run of length >= 2 survives once wildcards and path
    separators are removed.
    """
    import re as _re
    if label is None:
        return False
    core = _re.sub(r"[*/\\\s.]", "", str(label))
    return bool(_re.search(r"[A-Za-z0-9]{2,}", core))


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


def _with_basename_alt(label):
    r"""Offer a file label's basename as a ``|`` alternative.

    A host collector may record a file by its full path (``C:\Temp\x.dll``) or by
    a basename the analyst normalized to (``x.dll``); the PoC fixes only one form.
    When the label carries a path, add ``*basename*`` as an alternative so either
    recorded form aligns. Only for a distinctive basename (a dotted extension, or
    a long token) to avoid matching on a generic component. Returns the label
    unchanged when it has no path separator or no distinctive basename.
    """
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
    """Concrete executable label for a spawned child, or wildcard if dynamic.

    A spawn operand is often a whole command line (``rundll32.exe payload.dll,Main``)
    while a process collector records the child by its image name (``rundll32.exe``).
    The command line is kept as the primary label, with the image name offered as
    a ``|`` alternative so either recorded form aligns.
    """
    import re as _re
    lbl = _clean_label(raw)
    if lbl is None or str(lbl).strip() in ("", "*") or str(lbl).startswith("*"):
        # A command line assembled from literals and variables ("curl ... " + host
        # + ":" + port + "/_bulk") is not a single literal, but the part the PoC
        # fixes still names the program. Fold it the same way a file operand is
        # folded rather than discarding the whole operand.
        folded = _fold_str(raw)
        if folded is None or folded.strip("*") == "" or folded.startswith("*"):
            return "*.(executable)"
        lbl = folded
    full = _path_tolerance(str(lbl))
    # First token of the command line (honouring a quoted program path), reduced
    # to its basename -- the image name a process event carries.
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


def _inline_functions(tree, max_depth=3):
    r"""Inline user-defined function calls, binding arguments to parameters.

    Real PoCs route the request through helpers (``def exploit(t): url = t +
    '/cli'; download(url=url)``), so the endpoint is only reachable across a
    call. Following the paper's depth-3 inlining, we replace a statement-level
    call to a user function with its body, prefixed by ``param = arg``
    assignments, so value propagation then resolves the operand. Conservative:
    statement-level calls only (bare ``f(...)`` or ``x = f(...)``), positional
    and keyword args, no recursion, bounded depth.
    """
    funcs = {n.name: n for n in ast.walk(tree)
             if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}

    def binds_for(fn, call):
        out = []
        names = [a.arg for a in fn.args.args]
        # A method's first parameter is ``self``; a ``self.m(args)`` call passes
        # no receiver in call.args, so drop it before aligning params to args.
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

    def inline_stmts(stmts, depth):
        out = []
        for st in stmts:
            call = None
            if isinstance(st, ast.Expr) and isinstance(st.value, ast.Call):
                call = st.value
            elif isinstance(st, ast.Assign) and isinstance(st.value, ast.Call):
                call = st.value
            fn = user_call(call) if call is not None else None
            if fn is not None and depth < max_depth and fn.name != getattr(fn, "_inlining", None):
                import copy as _copy
                body = [_copy.deepcopy(s) for s in fn.body]
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
    r"""Substitute string-valued instance attributes before extraction.

    Class-based PoCs set the target in ``__init__`` (``self.base_url =
    'http://' + host``) and build requests from it (``self.base_url + path``).
    Value propagation over local names misses these, so the request path is
    lost. We collect every ``self.<attr>`` assigned a single string-valued
    expression and replace each later ``self.<attr>`` read with that
    expression, so the existing propagation and folding recover the path.
    """
    assigns, counts = {}, {}

    def stringy(n):
        return (isinstance(n, ast.Constant) and isinstance(n.value, str)) \
            or isinstance(n, ast.JoinedStr) \
            or (isinstance(n, ast.BinOp) and isinstance(n.op, (ast.Add, ast.Mod))
                and (stringy(n.left) or stringy(n.right)))

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            t = node.targets[0]
            if isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name) \
                    and t.value.id == "self":
                counts[t.attr] = counts.get(t.attr, 0) + 1
                if stringy(node.value):
                    assigns.setdefault(t.attr, node.value)
    keep = {a: v for a, v in assigns.items() if counts.get(a) == 1}
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

        # --- HTTP request ---
        if kind == "http":
            url = _resolve_operand(args, kwargs, rec, "http")
            query = _query_body_anchor(kwargs)
            if locus == "remote":
                # Target view (R*): the request the monitored host records, as a
                # resource the vulnerable service reads or writes.
                if "method_arg" in rec:
                    verb = _http_class_from_method(_arg_at(args, rec["method_arg"]) or kwargs.get("method"))
                else:
                    verb = rec.get("class", "write")
                base = _http_resource_label(url) if url is not None else None
                # A collector logs the whole request line, so query/body params
                # (params=, data=, json=) are part of the resource the target
                # records -- often where the discriminating anchor lives.
                path = _merge_query(base, query)
                if not _contentful(path):
                    # No concrete resource token: an anonymous operand, dropped.
                    path = _fresh_wildcard()
                    path_label = path
                else:
                    # Offer, as | alternatives, the forms the trace may have
                    # recorded: the full path+query and the path alone (a query
                    # the log omitted, e.g. a webshell logged only by its path).
                    # The concrete query VALUE is kept as a discriminator rather
                    # than wildcarded -- a bare name=* matches any request to that
                    # route and is a cross-CVE false positive.
                    alts = [path]
                    if query is not None and base is not None and base != path:
                        alts.append(base)
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
                # Local locus: the request is a transmission the runner emits
                # (delivery). It is a connection to a peer named by the URL, not
                # a target-side resource -- the runner never records the service
                # reading it. Represented as the sig's local shape: an outbound
                # connection between the runner and the endpoint.
                peer = _http_endpoint_label(url) if url is not None else None
                peer = _merge_query(peer, query)
                if not _contentful(peer):
                    peer = _fresh_wildcard()
                    peer_label = peer
                else:
                    # Offer the coarser endpoint forms an attacker-host graph may
                    # have recorded (service prefix, host:port) as | alternatives.
                    alts = _coarse_peer_alts(peer, url)
                    peer_label = " | ".join(alts) if len(alts) > 1 else peer
                output_graph.add_node(peer, node_info=Node(peer, "Socket", peer_label))
                # Outbound only: the runner reaches the endpoint. A reverse edge
                # would demand the endpoint reach back to the runner, which need
                # not hold when the actual connector is a descendant process the
                # k-tolerant path reaches forward but not in reverse.
                output_graph.add_edge(base_process_node, peer, syscall="connect")
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
                if rec.get("reg") and not str(label).startswith("*"):
                    # A registry write is recorded under its hive (HKLM\...); the
                    # winreg subkey the PoC names omits that prefix, so anchor it
                    # with a leading wildcard.
                    label = "*" + str(label)
                label = _with_basename_alt(label)
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

    # A template with no discriminating anchor -- only structural wildcards like
    # a *.(executable) -> *.(executable) spawn -- matches any provenance with the
    # same shape (every host spawns processes), so it is a universal false
    # positive. Emit nothing unless some node carries a concrete label.
    if not any(_discriminating(info.label) for info in keep.values()):
        with open(out_path, "w", encoding="utf-8") as f:
            f.write("")
        return

    lines = []
    for nid, info in keep.items():
        t = _NODE_TYPE_TO_SIG.get(info.type, "file")
        # A label must stay on one line; collapse any embedded newline/CR/tab a
        # multi-line string operand may have carried in.
        label = str(info.label).replace("\r", " ").replace("\n", " ").replace("\t", " ").strip()
        if not label:
            label = "*"
        lines.append(f"NODE {id_map[nid]} {t} {label}")
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


def _split_remote_anchors(output_graph):
    """One template per recorded request, for a remote-locus graph.

    A remote-locus PoC that issues several requests attaches each as a resource
    the target reads/writes off the shared ``net_client -> proc_host`` pair. The
    trace records only the requests that actually reached the vulnerable service,
    so a single template demanding *all* of them over-constrains (a pre-flight
    check the log missed blocks the whole alignment). Each request is an
    independent exploit-template candidate, so emit the client/host pair plus one
    resource at a time; detection holds if any single recorded request aligns.
    Returns a list of graphs (the input unchanged when it has 0/1 resources).
    """
    client_id, host_id = "net_client", "proc_host"
    if client_id not in output_graph or host_id not in output_graph:
        return [output_graph]
    resources = [v for _, v in output_graph.out_edges(host_id) if v != host_id]
    resources = list(dict.fromkeys(resources))
    if len(resources) <= 1:
        graphs = [output_graph]
        # Same client-less variant for a single-request template.
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
        # The requesting client is structural, not evidentiary: a collector may
        # record only the server-side effect (the service touching the resource)
        # without a matching network vertex. Also emit the host->resource pair
        # alone so such a trace still contains the template.
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
    """The full local-locus graph plus one single-anchor template per distinctive
    artifact.

    A local PoC may perform several operations (write a payload, probe a URL,
    trigger a fetch) of which the trace records only some. Keeping the whole
    graph over-constrains, so besides it, emit a template for each distinctive
    leaf file/net artifact (the acting process + that one artifact). Detection
    holds if the full chain OR any single recorded artifact aligns.
    """
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
        tree = _inline_functions(tree)
        tree = _inline_self_attrs(tree)
        handle_tree(tree, filename, foldername, output_graph, process_id)

        # Skip graphs that carry no syscall edges (pure control-flow stubs).
        if output_graph.number_of_edges() == 0:
            continue

        # A remote-locus graph with several recorded requests yields one template
        # per request (each an independent detection candidate); other graphs are
        # emitted whole.
        if locus == "remote":
            parts = _split_remote_anchors(output_graph)
        elif locus == "local":
            parts = _split_local_anchors(output_graph)
        else:
            parts = [output_graph]
        for sub, g in enumerate(parts):
            if g.number_of_edges() == 0:
                continue
            # In-run dedupe by canonical signature (labels + syscall-labeled edges).
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
# def main():
#     convert_graph("examples/follina.py", "examples")

# if __name__ == "__main__":
#     main()
