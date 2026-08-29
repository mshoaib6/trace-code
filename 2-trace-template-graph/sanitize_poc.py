from __future__ import annotations

import argparse
import ast
import copy as _copy_mod
import json
import sys
from pathlib import Path
from typing import Iterable, List, Set, Tuple


HERE = Path(__file__).parent
DEFAULT_SYSCALL_MAP = HERE / "syscall_mapping.json"


import re as _re_preparse
_URL_IN_COMMENT_RE = _re_preparse.compile(r"https?://[^\s\"\'<>`]+")

_NAMESPACE_HOSTS = ("schemas.xmlsoap.org", "www.w3.org", "w3.org",
                    "schemas.microsoft.com", "schemas.openxmlformats.org",
                    "docs.oasis-open.org", "xmlns.com", "purl.org",
                    "schemas.android.com", "java.sun.com", "xml.apache.org",
                    "namespaces.")


def _extract_documented_url_path(source: str) -> str | None:
    comment_text = []
    for line in source.splitlines():
        hash_idx = line.find("#")
        if hash_idx >= 0:
            comment_text.append(line[hash_idx:])
    comment_text.append(source)
    blob = "\n".join(comment_text)
    urls = _URL_IN_COMMENT_RE.findall(blob)
    best = None
    best_score = (-1, -1)
    for url in urls:
        url = url.rstrip(".,;:)]}'\"\\")
        parts = url.split("://", 1)
        if len(parts) != 2 or "/" not in parts[1]:
            continue
        host_and_path = parts[1]
        slash = host_and_path.find("/")
        host = host_and_path[:slash]
        path = host_and_path[slash:]
        if path in ("/", ""):
            continue
        host_lower = host.lower()
        skip_hosts = ("github.com", "raw.githubusercontent.com", "gitlab.com",
                      "bitbucket.org", "stackoverflow.com", "twitter.com",
                      "x.com", "medium.com", "rhinosecuritylabs.com",
                      "nvd.nist.gov", "cve.org", "mitre.org", "exploit-db.com",
                      "packetstormsecurity.com", "snyk.io", "cvefeed.io",
                      "tenable.com", "rapid7.com", "youtube.com", "linkedin.com")
        if any(h in host_lower for h in skip_hosts):
            continue
        if any(h in host_lower for h in _NAMESPACE_HOSTS):
            continue
        pl = path.lower()
        if any(k in pl for k in ("application-security", "/blog", "/advisor", "/research",
                                 "/vulnerab", "/security/", "disclosure", "/cve-", "/news")):
            continue
        clean = pl.split("?", 1)[0]
        if any(clean.endswith(e) for e in (".zip", ".tar", ".gz", ".tgz", ".exe",
                                           ".msi", ".deb", ".rpm", ".jar", ".whl",
                                           ".pdf", ".png", ".jpg", ".gif", ".svg")):
            continue
        generic_host = any(tok in host_lower for tok in ("example.com", "target.example"))
        depth = path.count("/")
        score = (depth - (1 if generic_host else 0), len(path))
        if score > best_score:
            best_score = score
            best = path
    if not best:
        return None
    if "?" in best:
        best = best.split("?", 1)[0] + "*"
    return best


NON_IOC_CALLS = {
    "print()",
    "input()",
    "sys.stdout.write()",
    "argparse.ArgumentParser().print_help()",
    "urllib3.disable_warnings()",
    "requests.packages.urllib3.disable_warnings()",
}


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
    name = _dotted_name(call.func)
    if name is None:
        return None
    return f"{name}()"


def _names_used(node: ast.AST) -> Set[str]:
    seen: Set[str] = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Name):
            seen.add(n.id)
    return seen


def _names_bound(stmt: ast.AST) -> Set[str]:
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


def _assign_keys(node: ast.AST) -> List[str]:
    targets: List[ast.AST] = []
    if isinstance(node, ast.Assign):
        targets = list(node.targets)
    elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
        targets = [node.target]
    out: List[str] = []
    for t in targets:
        if not isinstance(t, ast.Attribute):
            continue
        dotted = _dotted_name(t)
        if dotted:
            out.append(f"{dotted}=")
        out.append(f"{t.attr}=")
    return out


def _contains_anchor(stmt: ast.AST, relevant_keys: Set[str]) -> bool:
    for n in ast.walk(stmt):
        if isinstance(n, ast.Call):
            k = _call_key(n)
            if k is not None and k in relevant_keys and k not in NON_IOC_CALLS:
                return True
        elif isinstance(n, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            if any(k in relevant_keys for k in _assign_keys(n)):
                return True
    return False


_CONTROL_WITH_BODY = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.With,
                      ast.AsyncWith, ast.Try, ast.FunctionDef,
                      ast.AsyncFunctionDef)


def _is_pure_nuisance_expr(stmt: ast.stmt) -> bool:
    if not isinstance(stmt, ast.Expr):
        return False
    if not isinstance(stmt.value, ast.Call):
        return False
    k = _call_key(stmt.value)
    return k in NON_IOC_CALLS


def _prune_body(body: List[ast.stmt], relevant_keys: Set[str],
                deps: Set[str]) -> List[ast.stmt]:
    keep_idx: Set[int] = set()
    needed: Set[str] = set(deps)

    for i, stmt in enumerate(body):
        if _is_pure_nuisance_expr(stmt):
            continue
        if _contains_anchor(stmt, relevant_keys):
            keep_idx.add(i)
            needed |= _names_used(stmt)

    for i, stmt in enumerate(body):
        if isinstance(stmt, _CONTROL_WITH_BODY):
            if _contains_anchor(stmt, relevant_keys):
                keep_idx.add(i)
                for attr in ("test", "iter"):
                    guard = getattr(stmt, attr, None)
                    if guard is not None:
                        needed |= _names_used(guard)

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

    for i, stmt in enumerate(body):
        if isinstance(stmt, (ast.Import, ast.ImportFrom)):
            if _names_bound(stmt) & needed:
                keep_idx.add(i)

    out: List[ast.stmt] = []
    for i, stmt in enumerate(body):
        if i not in keep_idx:
            continue
        out.append(_prune_nested(stmt, relevant_keys, needed))
    return out


def _prune_nested(stmt: ast.stmt, relevant_keys: Set[str], deps: Set[str]) -> ast.stmt:
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


def _drop_unused_imports(tree: ast.Module) -> None:
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
                st.names = [a for a in st.names if (a.asname or a.name.split(".")[0]) in used]
                if st.names:
                    kept.append(st)
            continue
        kept.append(st)
    tree.body = kept


class _ExtractLiteralPath(ast.NodeTransformer):

    def _extract_literal(self, node: ast.AST, _depth: int = 0,
                         _expanding: frozenset = frozenset()) -> str | None:
        if _depth > 16:
            return None
        if isinstance(node, ast.Name):
            if node.id in _expanding:
                return None
            resolved = self._resolve(node)
            if resolved is node:
                return None
            return self._extract_literal(resolved, _depth + 1, _expanding | {node.id})
        node = self._resolve(node)
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.JoinedStr):
            parts = [v.value for v in node.values
                     if isinstance(v, ast.Constant) and isinstance(v.value, str)]
            return "".join(parts) if parts else None
        if isinstance(node, ast.BinOp):
            if isinstance(node.op, ast.Add):
                left = self._extract_literal(node.left, _depth + 1, _expanding) or ""
                right = self._extract_literal(node.right, _depth + 1, _expanding) or ""
                combined = left + right
                return combined or None
            if isinstance(node.op, ast.Mod):
                return self._extract_literal(node.left, _depth + 1, _expanding)
        if isinstance(node, ast.IfExp):
            for branch in (node.body, node.orelse):
                lit = self._extract_literal(branch, _depth + 1, _expanding)
                if lit:
                    return lit
            return None
        if isinstance(node, ast.Call):
            fn = _dotted_name(node.func)
            leaf = fn.rsplit(".", 1)[-1] if fn else None
            if leaf in ("urljoin", "join") and len(node.args) >= 2:
                return self._extract_literal(node.args[-1], _depth + 1, _expanding)
            if leaf == "format" and isinstance(node.func, ast.Attribute):
                return self._extract_literal(node.func.value, _depth + 1, _expanding)
            if leaf in ("quote", "quote_plus", "unquote", "urlencode") and node.args:
                return self._extract_literal(node.args[0], _depth + 1, _expanding)
        return None

    fallback_url: str | None = None
    scope_maps: dict = None
    var_map: dict = None

    def set_var_maps(self, maps: dict) -> None:
        self.scope_maps = maps or {}
        self.var_map = dict((self.scope_maps.get(None) or ({}, set()))[0])

    def _visit_scope(self, node: ast.AST) -> ast.AST:
        outer = self.var_map
        entry = (self.scope_maps or {}).get(id(node))
        if entry is not None:
            local, bound = entry
            merged = {k: v for k, v in (outer or {}).items() if k not in bound}
            merged.update(local)
            self.var_map = merged
        self.generic_visit(node)
        self.var_map = outer
        return node

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
        return self._visit_scope(node)

    def visit_AsyncFunctionDef(self, node) -> ast.AST:
        return self._visit_scope(node)

    argparse_defaults: dict = None

    def _resolve(self, node: ast.AST, seen: Set[str] | None = None) -> ast.AST:
        if seen is None:
            seen = set()
        if isinstance(node, ast.Name) and self.var_map and node.id in self.var_map:
            if node.id in seen:
                return node
            seen.add(node.id)
            return self._resolve(self.var_map[node.id], seen)
        if (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
                and node.value.id in ("args", "options", "opts", "arguments", "config")
                and self.argparse_defaults and node.attr in self.argparse_defaults):
            return self.argparse_defaults[node.attr]
        return node

    def _rewrite_url_arg(self, arg: ast.AST) -> ast.AST:
        literal = self._extract_literal(arg)
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
            return ast.Constant(value="*" + path + "*")
        if self.fallback_url:
            return ast.Constant(value=self.fallback_url)
        return arg

    _HTTP_CALL_ATTRS = {"get", "post", "put", "delete", "head", "patch",
                        "requests_get", "requests_post", "requests_put",
                        "requests_delete", "requests_head", "requests_patch"}

    def _is_http_call(self, call: ast.Call) -> bool:
        name = _dotted_name(call.func)
        if name is None:
            return False
        last = name.rsplit(".", 1)[-1]
        return last in self._HTTP_CALL_ATTRS

    _URL_KWARGS = ("url", "uri", "endpoint", "path")
    _QUERY_KWARGS = ("params", "data", "json")

    def _inline_query_kws(self, keywords):
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

    _METHODS = {"GET", "POST", "PUT", "DELETE", "HEAD", "PATCH"}
    _VERBS = {"get", "post", "put", "delete", "head", "patch"}

    _WRAPPER_SUFFIXES = (".request", ".send_request", ".do_request", ".make_request",
                         ".http_request", ".send")

    _HTTP_KWARGS = {"verify", "headers", "data", "json", "files", "params",
                    "cookies", "auth", "allow_redirects", "timeout", "proxies",
                    "stream", "url"}
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
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr.replace("requests_", "") in self._VERBS:
            func = ast.Attribute(value=func.value, attr=func.attr.replace("requests_", ""), ctx=func.ctx)
            node = ast.Call(func=func, args=node.args, keywords=node.keywords)
            kwnames = {kw.arg for kw in node.keywords if kw.arg}
            if self._is_session_recv(func.value) or (kwnames & self._HTTP_KWARGS):
                new_func = ast.Attribute(value=ast.Name(id="requests", ctx=ast.Load()),
                                         attr=func.attr, ctx=ast.Load())
                return ast.Call(func=new_func, args=node.args, keywords=node.keywords)
        is_wrapper = any(name.endswith(s) for s in self._WRAPPER_SUFFIXES)
        if not is_wrapper:
            return node
        if len(node.args) < 2:
            kw = {k.arg: k.value for k in node.keywords if k.arg}
            loc = next((kw[n] for n in ("path", "url", "uri", "endpoint") if n in kw), None)
            if loc is None:
                return node
            m = kw.get("method")
            verb = "post"
            if isinstance(m, ast.Constant) and isinstance(m.value, str) and m.value.upper() in self._METHODS:
                verb = m.value.lower()
            rest = [k for k in node.keywords
                    if k.arg not in ("method", "path", "url", "uri", "endpoint")]
            return ast.Call(
                func=ast.Attribute(value=ast.Name(id="requests", ctx=ast.Load()),
                                   attr=verb, ctx=ast.Load()),
                args=[loc], keywords=rest)
        method_arg = node.args[0]
        method = None
        if isinstance(method_arg, ast.Constant) and isinstance(method_arg.value, str):
            m = method_arg.value.upper()
            if m in self._METHODS:
                method = m.lower()
        if method is None:
            method = "post"
        new_func = ast.Attribute(
            value=ast.Name(id="requests", ctx=ast.Load()),
            attr=method,
            ctx=ast.Load(),
        )
        return ast.Call(func=new_func, args=node.args[1:], keywords=node.keywords)


class _CollapseTryExcept(ast.NodeTransformer):

    def visit_Try(self, node: ast.Try) -> ast.AST:
        body = [self.visit(s) for s in node.body]
        if node.orelse:
            body.extend(self.visit(s) for s in node.orelse)
        if node.finalbody:
            body.extend(self.visit(s) for s in node.finalbody)
        return body or [ast.Pass()]


def _ensure_requests_import(tree: ast.Module) -> None:
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


_SCOPE_TYPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)


def _iter_scope_stmts(scope: ast.AST):
    stack = list(getattr(scope, "body", []) or [])
    while stack:
        node = stack.pop()
        if isinstance(node, _SCOPE_TYPES):
            continue
        yield node
        stack.extend(ast.iter_child_nodes(node))


def _binds_name(node: ast.AST):
    out = []
    if isinstance(node, ast.Assign):
        for t in node.targets:
            out.extend(n.id for n in ast.walk(t) if isinstance(n, ast.Name))
    elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
        out.extend(n.id for n in ast.walk(node.target) if isinstance(n, ast.Name))
    elif isinstance(node, (ast.For, ast.AsyncFor)):
        out.extend(n.id for n in ast.walk(node.target) if isinstance(n, ast.Name))
    elif isinstance(node, ast.ExceptHandler) and node.name:
        out.append(node.name)
    elif isinstance(node, (ast.With, ast.AsyncWith)):
        for item in node.items:
            if item.optional_vars is not None:
                out.extend(n.id for n in ast.walk(item.optional_vars)
                           if isinstance(n, ast.Name))
    elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        out.append(node.name)
    return out


def _param_names(scope: ast.AST):
    a = getattr(scope, "args", None)
    if a is None:
        return []
    names = [x.arg for x in list(getattr(a, "posonlyargs", []) or []) + list(a.args) + list(a.kwonlyargs)]
    for extra in (a.vararg, a.kwarg):
        if extra is not None:
            names.append(extra.arg)
    return names


def _scope_var_map(scope: ast.AST):
    counts: dict = {}
    candidate: dict = {}
    bound = set(_param_names(scope))
    for node in _iter_scope_stmts(scope):
        bound.update(_binds_name(node))
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
    return ({n: candidate[n] for n in candidate if counts[n] == 1}, bound)


def _collect_var_map(tree: ast.Module) -> dict:
    maps = {None: _scope_var_map(tree)}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            maps[id(node)] = _scope_var_map(node)
    return maps


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


class _SubstituteArgparseDefaults(ast.NodeTransformer):

    _NS = ("args", "options", "opts", "arguments", "config", "parsed")

    def __init__(self, defaults):
        self.defaults = defaults or {}

    def visit_Attribute(self, node):
        self.generic_visit(node)
        if (isinstance(node.value, ast.Name) and node.value.id in self._NS
                and node.attr in self.defaults):
            return ast.copy_location(_copy_mod.deepcopy(self.defaults[node.attr]), node)
        return node


def _anchor_bearing_locals(tree: ast.AST, relevant_keys: Set[str]) -> Set[str]:
    classes = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)}
    methods_of = {
        name: {m.name for m in cls.body
               if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))}
        for name, cls in classes.items()
    }
    defs = {n.name: n for n in ast.walk(tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    bearing: Set[str] = set()
    bearing_classes: Set[str] = set()
    changed = True
    while changed:
        changed = False
        keys = set(relevant_keys)
        for b in bearing:
            keys.add(f"{b}()")
            keys.add(f"self.{b}()")
        keys |= {f"{c}()" for c in bearing_classes}
        for name, fn in defs.items():
            if name in bearing:
                continue
            if _contains_anchor(fn, keys):
                bearing.add(name)
                changed = True
        for name, cls in classes.items():
            if name in bearing_classes:
                continue
            if _contains_anchor(cls, keys):
                bearing_classes.add(name)
                changed = True

    out = {f"{n}()" for n in bearing} | {f"{c}()" for c in bearing_classes}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Name) or not isinstance(node.value, ast.Call):
            continue
        cname = _dotted_name(node.value.func)
        if cname not in classes:
            continue
        for m in methods_of.get(cname, ()):
            if m in bearing:
                out.add(f"{target.id}.{m}()")
    return out


def sanitize(source: str, relevant_keys: Set[str], keep_call_chain: bool = False) -> str:
    tree = ast.parse(source)
    tree = _NormalizePathlib().visit(tree)
    tree = _NormalizeHttpWrappers(_collect_session_vars(tree)).visit(tree)
    fallback = _extract_documented_url_path(source)
    extractor = _ExtractLiteralPath()
    extractor.fallback_url = fallback
    extractor.set_var_maps(_collect_var_map(tree))
    _apd = _collect_argparse_defaults(tree)
    extractor.argparse_defaults = _apd
    tree = _SubstituteArgparseDefaults(_apd).visit(tree)
    tree = extractor.visit(tree)
    _restrict_to_best_paths(tree, keep=8)
    tree = _CollapseTryExcept().visit(tree)
    _ensure_requests_import(tree)
    ast.fix_missing_locations(tree)

    if keep_call_chain:
        relevant_keys = set(relevant_keys) | _anchor_bearing_locals(tree, relevant_keys)

    deps: Set[str] = set()
    tree.body = _prune_body(tree.body, relevant_keys, deps)

    def _strip_docstrings(stmts: List[ast.stmt]) -> List[ast.stmt]:
        if stmts and isinstance(stmts[0], ast.Expr) and isinstance(stmts[0].value, ast.Constant) \
                and isinstance(stmts[0].value.value, str):
            stmts = stmts[1:]
        return stmts

    tree.body = _strip_docstrings(tree.body)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            node.body = _strip_docstrings(node.body) or [ast.Pass()]

    _drop_unused_imports(tree)

    return ast.unparse(tree) + "\n"


def load_relevant_keys(syscall_map_path: Path = DEFAULT_SYSCALL_MAP) -> Set[str]:
    return set(json.loads(syscall_map_path.read_text()))


_MATCH_STMT_RE = _re_preparse.compile(r"^(\s*)match\b.*:\s*$", _re_preparse.MULTILINE)
_CASE_STMT_RE = _re_preparse.compile(r"^(\s*)case\b.*:\s*$", _re_preparse.MULTILINE)


def _lower_py310_syntax(source: str) -> str:
    source = _MATCH_STMT_RE.sub(r"\1if True:", source)
    source = _CASE_STMT_RE.sub(r"\1if True:", source)
    return source


def _py2_to_py3(source: str) -> str:
    try:
        from lib2to3 import refactor
        fixers = refactor.get_fixers_from_package("lib2to3.fixes")
        rt = refactor.RefactoringTool(fixers)
        return str(rt.refactor_string(source + "\n", "poc"))
    except Exception:
        return source


def _sanitize_file(src: Path, dst: Path | None, keys: Set[str],
                   keep_call_chain: bool = False) -> str:
    source = src.read_text(encoding="utf-8", errors="replace")
    try:
        out = sanitize(source, keys, keep_call_chain)
    except SyntaxError:
        try:
            out = sanitize(_lower_py310_syntax(source), keys, keep_call_chain)
        except SyntaxError:
            try:
                out = sanitize(_lower_py310_syntax(_py2_to_py3(source)), keys, keep_call_chain)
            except SyntaxError as e3:
                print(f"    WARN  {src.name}: skipped (parse error: {e3.msg})", file=sys.stderr)
                out = ""
    if dst is not None:
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(out, encoding="utf-8")
    return out


def main() -> int:
    p = argparse.ArgumentParser(description="Sanitize a PoC for template extraction.")
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("filename", nargs="?", help="single input PoC .py")
    group.add_argument("--batch", help="directory of raw PoCs (*.py); writes to --out-dir")
    p.add_argument("--out", help="write sanitized output here (default stdout)")
    p.add_argument("--out-dir", help="with --batch, directory to write sanitized files to")
    p.add_argument("--syscall-map", default=str(DEFAULT_SYSCALL_MAP),
                   help="path to stage-2 syscall_mapping.json")
    p.add_argument("--keep-call-chain", action="store_true",
                   help="also keep calls to local functions that reach an anchor")
    args = p.parse_args()

    keys = load_relevant_keys(Path(args.syscall_map))

    if args.batch:
        if not args.out_dir:
            p.error("--batch requires --out-dir")
        src_dir = Path(args.batch)
        out_dir = Path(args.out_dir)
        n = 0
        for src in sorted(src_dir.glob("*.py")):
            _sanitize_file(src, out_dir / src.name, keys, args.keep_call_chain)
            print(f"  {src.name} -> {out_dir / src.name}")
            n += 1
        print(f"\nsanitized {n} file(s)")
        return 0

    src = Path(args.filename)
    out_text = _sanitize_file(src, Path(args.out) if args.out else None, keys,
                              args.keep_call_chain)
    if not args.out:
        sys.stdout.write(out_text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
