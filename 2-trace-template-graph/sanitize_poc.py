"""
sanitize_poc.py — strip a raw public PoC down to its log-evident operations.

Given any messy Python exploit (argparse, colorama banners, helper wrappers,
error handling), this produces the minimal PoC stub that stage 2 needs: only
the calls whose signatures appear in ``syscall_mapping.json`` (the API to
syscall footprint table) plus the assignments those calls depend on.

The same sanitizer is applied to every file in ``poc_splunk/`` — running it on
a raw public PoC should reproduce the hand-simplified stub used for evaluation.

Usage:
    python3 sanitize_poc.py path/to/raw_poc.py > sanitized.py
    python3 sanitize_poc.py --in raw_poc.py --out sanitized.py
    python3 sanitize_poc.py --batch raw_pocs/ --out-dir sanitized/

Design notes:
  * We walk the AST and collect ast.Call nodes whose normalized name is a key
    in ``syscall_mapping.json`` (e.g., ``requests.post()``, ``subprocess.run()``,
    ``open()``). Those are the "log-evident anchors".
  * From each anchor we trace variable dependencies transitively across
    assignments, keeping any statement that (a) is an anchor call, or
    (b) assigns a name used by an anchor, or (c) imports a module used by
    either.
  * A statement is kept as-is (not re-synthesised); the sanitizer is
    non-invasive: it either keeps or drops each top-level / body statement.
  * Nested control flow (`if`, `for`, `with`, `try`) is recursed into: the
    outer construct is kept iff it contains at least one anchor after pruning,
    and its body is the pruned subset.
"""
from __future__ import annotations

import argparse
import ast
import json
import sys
from pathlib import Path
from typing import Iterable, List, Set, Tuple


HERE = Path(__file__).parent
DEFAULT_SYSCALL_MAP = HERE / "syscall_mapping.json"


# Regex matching any URL inside comments/docstrings — many public PoCs
# document the intended endpoint here even when the source uses a CLI arg.
import re as _re_preparse
_URL_IN_COMMENT_RE = _re_preparse.compile(r"https?://[^\s\"\'<>`]+")


def _extract_documented_url_path(source: str) -> str | None:
    """Scan raw source text for URLs appearing in comments/docstrings and
    return the most informative URL *path* (with a wildcard suffix). This lets
    us recover the canonical exploit endpoint even when the Python source
    itself takes the full URL from ``sys.argv`` / ``args.url``.

    Prefers URLs that (a) are not generic placeholders like ``example.com``
    and (b) have the deepest path. Returns just the path portion suitable for
    matching against nginx/suricata-derived provenance.
    """
    # Strip strings: we only want comments+docstrings, not URL literals inside
    # running-code f-strings. Simple heuristic: look for '#' lines or triple
    # quoted segments.
    comment_text = []
    for line in source.splitlines():
        hash_idx = line.find("#")
        if hash_idx >= 0:
            comment_text.append(line[hash_idx:])
    # Naive: also include full-source so we catch docstrings (triple-quoted
    # blocks). The URLs we're after are clearly documentation, and the bias
    # towards "most specific path" filters out any stray in-code URL that a
    # literal extractor should have caught first.
    comment_text.append(source)
    blob = "\n".join(comment_text)
    urls = _URL_IN_COMMENT_RE.findall(blob)
    best = None
    best_score = (-1, -1)
    for url in urls:
        url = url.rstrip(".,;:)]}'\"")
        # Drop scheme+host to get path.
        parts = url.split("://", 1)
        if len(parts) != 2 or "/" not in parts[1]:
            continue
        host_and_path = parts[1]
        slash = host_and_path.find("/")
        host = host_and_path[:slash]
        path = host_and_path[slash:]
        if path in ("/", ""):
            continue
        # Skip hosts we know are documentation references, not exploit targets:
        # GitHub/GitLab links (often in User-Agent headers) and generic
        # example.com placeholders used in prose.
        host_lower = host.lower()
        skip_hosts = ("github.com", "raw.githubusercontent.com", "gitlab.com",
                      "bitbucket.org", "stackoverflow.com", "twitter.com",
                      "x.com", "medium.com", "rhinosecuritylabs.com",
                      "nvd.nist.gov", "cve.org", "mitre.org", "exploit-db.com",
                      "packetstormsecurity.com", "snyk.io", "cvefeed.io",
                      "tenable.com", "rapid7.com", "youtube.com", "linkedin.com")
        if any(h in host_lower for h in skip_hosts):
            continue
        # A disclosure/blog link is documentation, not a request the trace
        # records; its path reads like prose (hyphenated words, the CVE id).
        pl = path.lower()
        if any(k in pl for k in ("application-security", "/blog", "/advisor", "/research",
                                 "/vulnerab", "/security/", "disclosure", "/cve-", "/news")):
            continue
        # A download/artifact link (a plugin .zip, an .exe) is not the exploited
        # endpoint either.
        clean = pl.split("?", 1)[0]
        if any(clean.endswith(e) for e in (".zip", ".tar", ".gz", ".tgz", ".exe",
                                           ".msi", ".deb", ".rpm", ".jar", ".whl",
                                           ".pdf", ".png", ".jpg", ".gif", ".svg")):
            continue
        generic_host = any(tok in host_lower for tok in ("example.com", "target.example"))
        # Score: more path segments and longer path = more specific.
        depth = path.count("/")
        score = (depth - (1 if generic_host else 0), len(path))
        if score > best_score:
            best_score = score
            best = path
    if not best:
        return None
    # Truncate query string, append wildcard for matching tolerance.
    if "?" in best:
        best = best.split("?", 1)[0] + "*"
    return best


# API names that live in the syscall_mapping only for infrastructure reasons
# (stdout chatter, CLI option parsing, TLS warning suppression). They don't
# anchor any exploit behaviour, so the sanitizer treats them as non-IoC.
NON_IOC_CALLS = {
    "print()",
    "input()",
    "sys.stdout.write()",
    "argparse.ArgumentParser().print_help()",
    "urllib3.disable_warnings()",
    "requests.packages.urllib3.disable_warnings()",
}


# ---------------------------------------------------------------------------
# Call-name normalization (mirrors helpers.recur_through_attributes behaviour).
# ---------------------------------------------------------------------------

def _dotted_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        return f"{base}.{node.attr}" if base is not None else None
    if isinstance(node, ast.Call):
        base = _dotted_name(node.func)
        return f"{base}()" if base is not None else None
    return None


def _call_key(call: ast.Call) -> str | None:
    """Return a normalized `module.func()` key (lookup-compatible with syscall_mapping.json)."""
    name = _dotted_name(call.func)
    if name is None:
        return None
    return f"{name}()"


# ---------------------------------------------------------------------------
# Dependency tracking.
# ---------------------------------------------------------------------------

def _names_used(node: ast.AST) -> Set[str]:
    seen: Set[str] = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Name):
            seen.add(n.id)
    return seen


def _names_bound(stmt: ast.AST) -> Set[str]:
    """Names this statement writes (LHS of Assign/AugAssign, imports, defs, etc.)."""
    out: Set[str] = set()
    if isinstance(stmt, ast.Assign):
        for target in stmt.targets:
            for n in ast.walk(target):
                if isinstance(n, ast.Name):
                    out.add(n.id)
    elif isinstance(stmt, (ast.AugAssign, ast.AnnAssign)):
        if isinstance(stmt.target, ast.Name):
            out.add(stmt.target.id)
    elif isinstance(stmt, ast.Import):
        for alias in stmt.names:
            out.add(alias.asname or alias.name.split(".")[0])
    elif isinstance(stmt, ast.ImportFrom):
        for alias in stmt.names:
            out.add(alias.asname or alias.name)
    elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        out.add(stmt.name)
    return out


def _contains_anchor(stmt: ast.AST, relevant_keys: Set[str]) -> bool:
    for n in ast.walk(stmt):
        if isinstance(n, ast.Call):
            k = _call_key(n)
            if k is not None and k in relevant_keys and k not in NON_IOC_CALLS:
                return True
    return False


# ---------------------------------------------------------------------------
# Statement-level pruning.
# ---------------------------------------------------------------------------

_CONTROL_WITH_BODY = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.With,
                      ast.AsyncWith, ast.Try, ast.FunctionDef,
                      ast.AsyncFunctionDef)


def _is_pure_nuisance_expr(stmt: ast.stmt) -> bool:
    """True if the statement is a standalone call to a non-IoC helper
    (print, input, disable_warnings...) — safe to strip outright."""
    if not isinstance(stmt, ast.Expr):
        return False
    if not isinstance(stmt.value, ast.Call):
        return False
    k = _call_key(stmt.value)
    return k in NON_IOC_CALLS


def _prune_body(body: List[ast.stmt], relevant_keys: Set[str],
                deps: Set[str]) -> List[ast.stmt]:
    """Keep statements that contain an anchor call, transitively plus the
    assignments/imports they depend on. Works on a single body list."""
    # First pass (reverse): compute which names each anchor statement needs.
    keep_idx: Set[int] = set()
    needed: Set[str] = set(deps)

    # Mark direct anchor statements first; drop pure-nuisance expressions.
    for i, stmt in enumerate(body):
        if _is_pure_nuisance_expr(stmt):
            continue
        if _contains_anchor(stmt, relevant_keys):
            keep_idx.add(i)
            needed |= _names_used(stmt)

    # Recurse into nested control flow statements to discover deeper anchors.
    for i, stmt in enumerate(body):
        if isinstance(stmt, _CONTROL_WITH_BODY):
            if _contains_anchor(stmt, relevant_keys):
                keep_idx.add(i)
                # Names used in the guard/header (if/for/while condition)
                for attr in ("test", "iter"):
                    guard = getattr(stmt, attr, None)
                    if guard is not None:
                        needed |= _names_used(guard)

    # Back-propagate: statements that define names in `needed` are also kept.
    # Iterate to fixed point (new kept stmts can pull in more names).
    changed = True
    while changed:
        changed = False
        for i, stmt in enumerate(body):
            if i in keep_idx:
                continue
            bound = _names_bound(stmt)
            if bound & needed:
                keep_idx.add(i)
                needed |= _names_used(stmt)
                changed = True

    # Always keep imports that bind names used in any kept statement.
    for i, stmt in enumerate(body):
        if isinstance(stmt, (ast.Import, ast.ImportFrom)):
            if _names_bound(stmt) & needed:
                keep_idx.add(i)

    # Recurse into kept nested bodies to prune them too.
    out: List[ast.stmt] = []
    for i, stmt in enumerate(body):
        if i not in keep_idx:
            continue
        out.append(_prune_nested(stmt, relevant_keys, needed))
    return out


def _prune_nested(stmt: ast.stmt, relevant_keys: Set[str], deps: Set[str]) -> ast.stmt:
    """Replace inner bodies of control-flow statements with their pruned versions."""
    if isinstance(stmt, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith)):
        stmt.body = _prune_body(stmt.body, relevant_keys, deps) or [ast.Pass()]
        if hasattr(stmt, "orelse"):
            stmt.orelse = _prune_body(stmt.orelse, relevant_keys, deps)
    elif isinstance(stmt, ast.Try):
        stmt.body = _prune_body(stmt.body, relevant_keys, deps) or [ast.Pass()]
        stmt.orelse = _prune_body(stmt.orelse, relevant_keys, deps)
        stmt.finalbody = _prune_body(stmt.finalbody, relevant_keys, deps)
        for h in stmt.handlers:
            h.body = _prune_body(h.body, relevant_keys, deps) or [ast.Pass()]
    elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
        stmt.body = _prune_body(stmt.body, relevant_keys, deps) or [ast.Pass()]
    return stmt


# ---------------------------------------------------------------------------
# Top-level entry.
# ---------------------------------------------------------------------------

def _drop_unused_imports(tree: ast.Module) -> None:
    """After pruning, drop imports whose bound names don't appear in the
    remaining body. Saves us from carrying `import sys` / `colorama` stubs
    left over from helper code that was pruned."""
    def _body_names(stmts: List[ast.stmt]) -> Set[str]:
        s: Set[str] = set()
        for st in stmts:
            if isinstance(st, (ast.Import, ast.ImportFrom)):
                continue
            s |= _names_used(st)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for n in ast.walk(node):
                    if isinstance(n, ast.Name):
                        s.add(n.id)
        return s

    used = _body_names(tree.body)
    kept = []
    for st in tree.body:
        if isinstance(st, (ast.Import, ast.ImportFrom)):
            if _names_bound(st) & used:
                # Trim individual aliases within an import that are unused.
                st.names = [a for a in st.names if (a.asname or a.name.split(".")[0]) in used]
                if st.names:
                    kept.append(st)
            continue
        kept.append(st)
    tree.body = kept


class _ExtractLiteralPath(ast.NodeTransformer):
    """Inside HTTP calls, rewrite dynamic URL expressions so the concrete
    exploit path survives.

    ``base_url + '/_api/web/siteusers'``        -> ``'/_api/web/siteusers'``
    ``f'{self.url}/_api/web/siteusers'``        -> ``'/_api/web/siteusers'``
    ``f'{self.url}/cli?remoting=false'``        -> ``'/cli?remoting=false'``

    Our provenance graphs log the URL *path*, not the full URL with host,
    so dropping the host component keeps the label alignment working.
    This only runs on positional arguments to HTTP calls (``requests.get``
    etc.) — it leaves the rest of the PoC alone.
    """

    def _extract_literal(self, node: ast.AST, _depth: int = 0) -> str | None:
        """Return the concatenated literal portion, or None if nothing concrete."""
        if _depth > 16:
            return None
        node = self._resolve(node)
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.JoinedStr):
            parts = [v.value for v in node.values
                     if isinstance(v, ast.Constant) and isinstance(v.value, str)]
            return "".join(parts) if parts else None
        if isinstance(node, ast.BinOp):
            if isinstance(node.op, ast.Add):
                left = self._extract_literal(node.left, _depth + 1) or ""
                right = self._extract_literal(node.right, _depth + 1) or ""
                combined = left + right
                return combined or None
            if isinstance(node.op, ast.Mod):
                return self._extract_literal(node.left, _depth + 1)
        if isinstance(node, ast.IfExp):
            # ``args.out if args.out else "default.rar"`` -- a PoC's default
            # output name lives in one branch of a conditional; take whichever
            # branch yields a literal.
            for branch in (node.body, node.orelse):
                lit = self._extract_literal(branch, _depth + 1)
                if lit:
                    return lit
            return None
        if isinstance(node, ast.Call):
            fn = _dotted_name(node.func)
            leaf = fn.rsplit(".", 1)[-1] if fn else None
            # urljoin(base, path) / os.path.join(base, path): the last arg is the
            # distinctive path the trace records.
            if leaf in ("urljoin", "join") and len(node.args) >= 2:
                return self._extract_literal(node.args[-1], _depth + 1)
            # "/path/{}".format(x): the format template carries the literal path.
            if leaf == "format" and isinstance(node.func, ast.Attribute):
                return self._extract_literal(node.func.value, _depth + 1)
            # quote(x)/quote_plus(x)/unquote(x): URL-encoding is transparent to
            # the discriminating tokens.
            if leaf in ("quote", "quote_plus", "unquote", "urlencode") and node.args:
                return self._extract_literal(node.args[0], _depth + 1)
        return None

    #: set by sanitize() before .visit() — URL path extracted from source comments/docstrings
    fallback_url: str | None = None
    #: {name: ast-node} map of top-level + function-scoped simple assignments,
    #: so we can chase ``url = f'{host}/api/v1/foo'`` back when ``requests.get(url)``
    #: is called later.
    var_map: dict = None  # type: ignore

    #: {dest: Constant} argparse defaults, so args.endpoint resolves to its
    #: declared default literal.
    argparse_defaults: dict = None  # type: ignore

    def _resolve(self, node: ast.AST, seen: Set[str] | None = None) -> ast.AST:
        """If node is a Name that maps to a known assigned expression, return
        the assigned expression (recursively). Otherwise return node as-is."""
        if seen is None:
            seen = set()
        if isinstance(node, ast.Name) and self.var_map and node.id in self.var_map:
            if node.id in seen:
                return node
            seen.add(node.id)
            return self._resolve(self.var_map[node.id], seen)
        # args.endpoint / options.path -> the argparse default literal.
        if (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
                and node.value.id in ("args", "options", "opts", "arguments", "config")
                and self.argparse_defaults and node.attr in self.argparse_defaults):
            return self.argparse_defaults[node.attr]
        return node

    def _rewrite_url_arg(self, arg: ast.AST) -> ast.AST:
        """If the arg is a dynamic URL/path expression whose literal portion
        contains a leading slash, replace it with just that path.
        If no literal is recoverable but a documented URL path was parsed from
        the PoC's comments, fall back to that path."""
        literal = self._extract_literal(arg)
        # A bare web-resource filename (urljoin(base, 'shell.jsp')) denotes the
        # path /shell.jsp that the target records; treat it as a path anchor.
        if literal and "/" not in literal:
            import re as _re
            if _re.fullmatch(r"[A-Za-z0-9._-]{3,}\.(jsp|jspx|php|aspx|asp|ashx|cfm|do|action|cgi|html?)", literal):
                literal = "/" + literal
        if literal and "/" in literal:
            import re as _re
            m = _re.search(r"(/[^/].*)$", literal.split("://", 1)[-1])
            path = m.group(1) if m else literal[literal.find("/"):]
            if "?" in path:
                path = path.split("?", 1)[0]
            # Both leading and trailing wildcards: the prov label may carry
            # an app-specific prefix (e.g. /mifs/asfV3 + /api/v2/authorized/users)
            # that the PoC's f-string doesn't name as a literal, or extra
            # query/fragment suffixes we've already truncated.
            return ast.Constant(value="*" + path + "*")
        # No literal recoverable. If the PoC documents a URL example in its
        # comments, inject that path so the sig gets a concrete anchor.
        if self.fallback_url:
            return ast.Constant(value=self.fallback_url)
        return arg

    _HTTP_CALL_ATTRS = {"get", "post", "put", "delete", "head", "patch"}

    def _is_http_call(self, call: ast.Call) -> bool:
        """True iff this is a recognised HTTP-verb call on any object.

        After ``_NormalizeHttpWrappers`` runs, all PoC wrapper methods
        (``self.send_request``, ``http.client.HTTPConnection.request`` etc.)
        have been rewritten to ``requests.<verb>`` form, so this check is
        sufficient."""
        name = _dotted_name(call.func)
        if name is None:
            return False
        last = name.rsplit(".", 1)[-1]
        return last in self._HTTP_CALL_ATTRS

    _URL_KWARGS = ("url", "uri", "endpoint")
    _QUERY_KWARGS = ("params", "data", "json")

    def _inline_query_kws(self, keywords):
        """Replace params=/data=/json= that reference a dict *variable* with the
        dict literal, so stage 2 can read the query the request carries
        (``data = {'rest_route': '/pmpro/v1/order'}; requests.get(u, params=data)``)."""
        out = []
        for kw in keywords:
            if kw.arg in self._QUERY_KWARGS:
                resolved = self._resolve(kw.value)
                if isinstance(resolved, ast.Dict):
                    out.append(ast.keyword(arg=kw.arg, value=resolved))
                    continue
            out.append(kw)
        return out

    def visit_Call(self, node: ast.Call) -> ast.AST:
        self.generic_visit(node)
        if not self._is_http_call(node):
            return node
        # The URL is the first positional arg, or a url=/uri= keyword (many PoCs
        # write requests.get(url=...)). Rewrite whichever carries it; a query
        # passed as a dict variable is inlined so its params survive.
        kws = self._inline_query_kws(node.keywords)
        if node.args:
            new_args = [self._rewrite_url_arg(node.args[0])] + list(node.args[1:])
            return ast.Call(func=node.func, args=new_args, keywords=kws)
        new_kws = []
        for kw in kws:
            if kw.arg in self._URL_KWARGS:
                new_kws.append(ast.keyword(arg=kw.arg, value=self._rewrite_url_arg(kw.value)))
            else:
                new_kws.append(kw)
        return ast.Call(func=node.func, args=node.args, keywords=new_kws)


class _NormalizeHttpWrappers(ast.NodeTransformer):
    """Rewrite HTTP wrappers to concrete per-method calls stage 2 recognises.

    ``requests.request("POST", url, ...)``  ->  ``requests.post(url, ...)``
    ``session.request("GET", url, ...)``    ->  ``requests.get(url, ...)``

    Public PoCs often route all HTTP traffic through a single ``send_request``
    wrapper or use ``requests.request(method, url, ...)`` with a ``method``
    variable. Stage 2's syscall_mapping keys on concrete method names
    (``requests.get``, ``requests.post``), so we rewrite here."""

    _METHODS = {"GET", "POST", "PUT", "DELETE", "HEAD", "PATCH"}
    _VERBS = {"get", "post", "put", "delete", "head", "patch"}

    # Names of user-defined wrapper methods that are almost always HTTP dispatchers.
    _WRAPPER_SUFFIXES = (".request", ".send_request", ".do_request", ".make_request",
                         ".http_request", ".send")

    # Keyword arguments specific to requests/httpx verb calls; their presence
    # marks a .get/.post(...) as an HTTP call rather than e.g. dict.get.
    _HTTP_KWARGS = {"verify", "headers", "data", "json", "files", "params",
                    "cookies", "auth", "allow_redirects", "timeout", "proxies",
                    "stream", "url"}
    # Receiver attribute/name fragments that denote an HTTP session object.
    _SESSION_HINTS = ("session", "client", "http", "sess")

    def __init__(self, session_vars=None):
        self.session_vars = session_vars or set()

    def _is_session_recv(self, recv) -> bool:
        if isinstance(recv, ast.Name):
            return recv.id in self.session_vars or recv.id.lower() in self._SESSION_HINTS
        if isinstance(recv, ast.Attribute):
            return recv.attr.lower() in self._SESSION_HINTS
        return False

    def visit_Call(self, node: ast.Call) -> ast.AST:
        self.generic_visit(node)
        name = _dotted_name(node.func)
        if name is None:
            return node
        # A call on a requests/httpx session object -- session.get(url, ...) or
        # self.client.post(...) -- is an HTTP verb call, but stage 2 keys on
        # requests.<verb>; the receiver is often a parameter/attribute it cannot
        # trace back to requests.Session(). Rewrite <session>.<verb>(...) to
        # requests.<verb>(...) when the receiver looks like a session or the call
        # carries an HTTP-specific keyword (verify=/files=/data=/...).
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in self._VERBS:
            kwnames = {kw.arg for kw in node.keywords if kw.arg}
            if self._is_session_recv(func.value) or (kwnames & self._HTTP_KWARGS):
                new_func = ast.Attribute(value=ast.Name(id="requests", ctx=ast.Load()),
                                         attr=func.attr, ctx=ast.Load())
                return ast.Call(func=new_func, args=node.args, keywords=node.keywords)
        is_wrapper = any(name.endswith(s) for s in self._WRAPPER_SUFFIXES)
        if not is_wrapper:
            return node
        if len(node.args) < 2:
            return node
        method_arg = node.args[0]
        method = None
        if isinstance(method_arg, ast.Constant) and isinstance(method_arg.value, str):
            m = method_arg.value.upper()
            if m in self._METHODS:
                method = m.lower()
        if method is None:
            method = "post"  # most exploit wrappers are POST
        new_func = ast.Attribute(
            value=ast.Name(id="requests", ctx=ast.Load()),
            attr=method,
            ctx=ast.Load(),
        )
        return ast.Call(func=new_func, args=node.args[1:], keywords=node.keywords)


class _CollapseTryExcept(ast.NodeTransformer):
    """Replace ``try: body except: ...`` with just ``body``.

    In real-world exploit PoCs, try/except brackets are ubiquitous error
    handling that exists only to keep the script from crashing — they don't
    encode meaningful exploit branching. Collapsing them prevents stage 2's
    split_tree from producing an exponential blow-up of path variants when a
    PoC has many wrapped requests."""

    def visit_Try(self, node: ast.Try) -> ast.AST:
        body = [self.visit(s) for s in node.body]
        if node.orelse:
            body.extend(self.visit(s) for s in node.orelse)
        if node.finalbody:
            body.extend(self.visit(s) for s in node.finalbody)
        return body or [ast.Pass()]


def _ensure_requests_import(tree: ast.Module) -> None:
    """If any call references ``requests.<method>`` after normalization but
    there's no ``import requests`` in the module, prepend one so stage 2's
    import resolver picks it up."""
    has_import = False
    uses_requests = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "requests":
                    has_import = True
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and node.value.id == "requests":
                uses_requests = True
    if uses_requests and not has_import:
        tree.body.insert(0, ast.Import(names=[ast.alias(name="requests", asname=None)]))
        ast.fix_missing_locations(tree)


def _collect_var_map(tree: ast.Module) -> dict:
    """Build a ``{name: rhs-ast}`` map for simple single-target assignments at
    module scope AND inside each function body (separately).

    Keeps only names that are assigned *exactly once* across the whole file
    and whose RHS is a string-producing expression (Constant, JoinedStr, or
    BinOp with either). This biases toward the "one canonical URL variable"
    pattern (``url = f'{base}/api/foo'; requests.get(url)``) while rejecting
    helper-method locals that are reused across different call paths."""
    counts = {}
    candidate = {}
    for node in ast.walk(tree):
        targets = []
        rhs = None
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            targets = [node.targets[0].id]
            rhs = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None:
            targets = [node.target.id]
            rhs = node.value
        for name in targets:
            counts[name] = counts.get(name, 0) + 1
            if _looks_stringy(rhs):
                candidate.setdefault(name, rhs)
    return {n: candidate[n] for n in candidate if counts[n] == 1}


def _looks_stringy(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return isinstance(node.value, str)
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return _looks_stringy(node.left) or _looks_stringy(node.right)
    return False


_EXPLOIT_KEYWORDS = ("setup", "admin", "exec", "upload", "deploy", "shell",
                     "execute", "traversal", "rce", "config", "include",
                     "spinstall", "setupadministrator", "finishsetup",
                     "startwebview", "metadatauploader", "ctcwebservice",
                     "setupwizard", "cli", "evalfile", "dispatch",
                     "addlanguage", "newcode", "doautoupgrade", "plugins")

_HELPER_KEYWORDS = ("check", "auth", "verify", "health", "ping", "heartbeat",
                    "status", "version", "login_probe", "currentuser", "whoami")


def _restrict_to_best_paths(tree: ast.Module, keep: int = 1) -> None:
    """Rank extracted URL path constants with a heuristic that prefers real
    exploit anchors over pre-flight/helper checks, then keep the top-K
    distinct values. Everything else collapses to ``'*'``.

    Ranking signals (in order of priority):
    * The HTTP method of the enclosing call: POST/PUT/DELETE/PATCH beat GET.
    * Exploit keywords in the path (``setup``, ``admin``, etc.) add score.
    * Helper keywords (``check``, ``auth``) subtract score.
    * Deeper paths beat shallow ones; longer strings beat shorter.
    """
    # Map each path-Constant to the enclosing Call's HTTP method. Walk the
    # tree once, record parent-method for each Constant.
    node_to_method: dict[int, str] = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.Call) and n.args and isinstance(n.args[0], ast.Constant):
            name = _dotted_name(n.func)
            if name is None:
                continue
            verb = name.rsplit(".", 1)[-1].lower()
            if verb in ("get", "post", "put", "delete", "head", "patch"):
                node_to_method[id(n.args[0])] = verb

    path_consts = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Constant) and isinstance(n.value, str):
            v = n.value
            if v.startswith("*") and "/" in v:
                method = node_to_method.get(id(n), "get")
                score = _score_path(v, method)
                path_consts.append((score, v, n))
    if not path_consts:
        return
    # Pick the best score per distinct value.
    by_value: dict[str, int] = {}
    for score, v, _ in path_consts:
        if v not in by_value or score > by_value[v]:
            by_value[v] = score
    ranked = sorted(by_value.keys(), key=lambda v: by_value[v], reverse=True)
    survivors = set(ranked[:keep])
    for _, v, n in path_consts:
        if v not in survivors:
            n.value = "*"


def _score_path(path: str, method: str) -> int:
    lo = path.lower()
    score = 0
    if method in ("post", "put", "delete", "patch"):
        score += 100
    for kw in _EXPLOIT_KEYWORDS:
        if kw in lo:
            score += 20
    for kw in _HELPER_KEYWORDS:
        if kw in lo:
            score -= 30
    score += path.count("/") * 2
    score += len(path) // 8
    return score


_SESSION_FACTORIES = ("requests.session", "requests.Session", "httpx.Client",
                      "httpx.AsyncClient", "aiohttp.ClientSession")


class _NormalizePathlib(ast.NodeTransformer):
    """Rewrite pathlib file I/O to the ``open(path, mode)`` form stage 2 keys on.

    ``p.write_bytes(d)`` / ``p.write_text(d)`` / ``p.read_bytes()`` /
    ``p.read_text()`` name the file by the receiver ``p``; stage 2 recognises
    ``open(p, mode)`` where the path is the first argument. Rewrite so the file
    operand is visible."""

    _MODE = {"write_bytes": "wb", "write_text": "w", "read_bytes": "rb", "read_text": "r"}

    def visit_Call(self, node: ast.Call) -> ast.AST:
        self.generic_visit(node)
        f = node.func
        if isinstance(f, ast.Attribute) and f.attr in self._MODE and not isinstance(f.value, ast.Attribute):
            return ast.copy_location(
                ast.Call(func=ast.Name(id="open", ctx=ast.Load()),
                         args=[f.value, ast.Constant(value=self._MODE[f.attr])],
                         keywords=[]),
                node)
        return node


def _collect_argparse_defaults(tree: ast.Module) -> dict:
    """Map an argparse dest to its default string literal, so a PoC that reads
    the endpoint from ``args.<dest>`` (default '/foo') still yields the anchor."""
    out = {}
    for n in ast.walk(tree):
        if not (isinstance(n, ast.Call)):
            continue
        fn = _dotted_name(n.func)
        if not fn or not fn.endswith("add_argument"):
            continue
        opt_names = [a.value for a in n.args if isinstance(a, ast.Constant) and isinstance(a.value, str)]
        dest = None
        default = None
        for kw in n.keywords:
            if kw.arg == "dest" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                dest = kw.value.value
            if kw.arg == "default":
                default = kw.value
        if dest is None:
            longs = [o for o in opt_names if o.startswith("--")]
            base = (longs[0] if longs else (opt_names[0] if opt_names else None))
            if base:
                dest = base.lstrip("-").replace("-", "_")
        if dest and isinstance(default, ast.Constant) and isinstance(default.value, str):
            out[dest] = default
    return out


def _collect_session_vars(tree: ast.Module) -> Set[str]:
    """Names bound to a requests/httpx session object, so calls on them
    (``session.get(...)``) can be normalized to ``requests.<verb>``."""
    out: Set[str] = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign) and isinstance(n.value, ast.Call):
            fn = _dotted_name(n.value.func)
            if fn and any(fn == f or fn.endswith("." + f.split(".")[-1]) for f in _SESSION_FACTORIES):
                if fn.rsplit(".", 1)[-1] in ("session", "Session", "Client", "AsyncClient", "ClientSession"):
                    for t in n.targets:
                        if isinstance(t, ast.Name):
                            out.add(t.id)
    return out


def sanitize(source: str, relevant_keys: Set[str]) -> str:
    tree = ast.parse(source)
    tree = _NormalizePathlib().visit(tree)
    tree = _NormalizeHttpWrappers(_collect_session_vars(tree)).visit(tree)
    fallback = _extract_documented_url_path(source)
    extractor = _ExtractLiteralPath()
    extractor.fallback_url = fallback
    extractor.var_map = _collect_var_map(tree)
    extractor.argparse_defaults = _collect_argparse_defaults(tree)
    tree = extractor.visit(tree)
    # After extraction we may have N different extracted paths (one per
    # helper/phase). Stage 3 refinement is strictly injective, so if the
    # PoC does pre-flight checks the provenance log didn't capture, those
    # extra anchors block alignment. Keep only the 2 most-specific paths;
    # collapse the rest to generic wildcards.
    _restrict_to_best_paths(tree, keep=8)
    tree = _CollapseTryExcept().visit(tree)
    _ensure_requests_import(tree)
    ast.fix_missing_locations(tree)

    # Collect unconditional deps that will always survive.
    deps: Set[str] = set()
    tree.body = _prune_body(tree.body, relevant_keys, deps)

    # Strip docstrings (the very first Expr[str] in a module/function).
    def _strip_docstrings(stmts: List[ast.stmt]) -> List[ast.stmt]:
        if stmts and isinstance(stmts[0], ast.Expr) and isinstance(stmts[0].value, ast.Constant) \
                and isinstance(stmts[0].value.value, str):
            stmts = stmts[1:]
        return stmts

    tree.body = _strip_docstrings(tree.body)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            node.body = _strip_docstrings(node.body) or [ast.Pass()]

    # Drop imports whose names are no longer used after pruning.
    _drop_unused_imports(tree)

    return ast.unparse(tree) + "\n"


def load_relevant_keys(syscall_map_path: Path = DEFAULT_SYSCALL_MAP) -> Set[str]:
    return set(json.loads(syscall_map_path.read_text()))


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------

_MATCH_STMT_RE = _re_preparse.compile(r"^(\s*)match\b.*:\s*$", _re_preparse.MULTILINE)
_CASE_STMT_RE = _re_preparse.compile(r"^(\s*)case\b.*:\s*$", _re_preparse.MULTILINE)


def _lower_py310_syntax(source: str) -> str:
    """Linearise Python 3.10 ``match``/``case`` statements so a 3.9 ast can
    parse them. We don't need the match semantics — we only need the bodies
    (which contain the syscall-level calls) to survive. Both keywords become
    ``if True:`` which preserves indentation and block semantics."""
    source = _MATCH_STMT_RE.sub(r"\1if True:", source)
    source = _CASE_STMT_RE.sub(r"\1if True:", source)
    return source


def _py2_to_py3(source: str) -> str:
    """Best-effort Python-2 -> Python-3 conversion so an old PoC's syscall-level
    calls survive to stage 2. Uses lib2to3; returns the source unchanged if the
    conversion library is unavailable or errors."""
    try:
        from lib2to3 import refactor
        fixers = refactor.get_fixers_from_package("lib2to3.fixes")
        rt = refactor.RefactoringTool(fixers)
        return str(rt.refactor_string(source + "\n", "poc"))
    except Exception:
        return source


def _sanitize_file(src: Path, dst: Path | None, keys: Set[str]) -> str:
    source = src.read_text(encoding="utf-8", errors="replace")
    try:
        out = sanitize(source, keys)
    except SyntaxError:
        # Retry through the Python-3.10 match/case lowering, then a Python-2->3
        # conversion pass (many older exploit PoCs are Python 2).
        try:
            out = sanitize(_lower_py310_syntax(source), keys)
        except SyntaxError:
            try:
                out = sanitize(_lower_py310_syntax(_py2_to_py3(source)), keys)
            except SyntaxError as e3:
                print(f"    WARN  {src.name}: skipped (parse error: {e3.msg})", file=sys.stderr)
                out = ""
    if dst is not None:
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(out, encoding="utf-8")
    return out


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("filename", nargs="?", help="single input PoC .py")
    group.add_argument("--batch", help="directory of raw PoCs (*.py); writes to --out-dir")
    p.add_argument("--out", help="write sanitized output here (default stdout)")
    p.add_argument("--out-dir", help="with --batch, directory to write sanitized files to")
    p.add_argument("--syscall-map", default=str(DEFAULT_SYSCALL_MAP),
                   help="path to stage-2 syscall_mapping.json")
    args = p.parse_args()

    keys = load_relevant_keys(Path(args.syscall_map))

    if args.batch:
        if not args.out_dir:
            p.error("--batch requires --out-dir")
        src_dir = Path(args.batch)
        out_dir = Path(args.out_dir)
        n = 0
        for src in sorted(src_dir.glob("*.py")):
            _sanitize_file(src, out_dir / src.name, keys)
            print(f"  {src.name} -> {out_dir / src.name}")
            n += 1
        print(f"\nsanitized {n} file(s)")
        return 0

    src = Path(args.filename)
    out_text = _sanitize_file(src, Path(args.out) if args.out else None, keys)
    if not args.out:
        sys.stdout.write(out_text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
