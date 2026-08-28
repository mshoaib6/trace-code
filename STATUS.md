# STATUS — handoff

Working notes for whoever picks this up next. Branch: `pi-impacket-1675`.

## Where things stand

Stage-3 alignment on the shipped templates reproduces the reported evaluation:

```bash
cd 3-trace-align
python trace_batch_run.py --graphs_dir splunk_extend/graphs --trace_align ./trace_align.py   # 33/33
python trace_batch_run.py --graphs_dir poc_graphs/graphs    --trace_align ./trace_align.py   # 12/12
python trace_batch_run.py --graphs_dir splunk_extend/graphs --trace_align ./trace_align.py --all_pairs
# 45 alignments, P@1 33/33, cross-CVE false alerts 0/1044
```

Stage 2 over the 45 shipped PoCs:

```bash
cd 2-trace-template-graph
python compile_pocs.py ../3-trace-align/poc_real/poc sig_out    # 42/45 compile with >=1 edge
```

## BLOCKED — read this first

`3-trace-align/poc_real/poc/CVE-2021-1675.py` is **quarantined by Sophos endpoint AV**
on the origin machine. The file exists at 8348 bytes but no process can open it —
python, cat, wc and `git hash-object` all fail with
`PermissionError: [Errno 1] Operation not permitted`. It is therefore **not in this
commit** and must be re-fetched:

```
https://raw.githubusercontent.com/cube0x0/CVE-2021-1675/main/SharpPrintNightmare/CVE-2021-1675.py
```

Expected: 8359 bytes upstream; normalised sha256 (trailing whitespace stripped,
CRLF→LF) `40da7d072bfdc65b4af2c119d0924cab4afd38c5165567b938fb9407104127f7`, 181 lines.

Do not burn turns working around the AV block. Writing via a different mechanism
(Write tool, `python3 -c`, heredoc, base64 round-trip, rename-then-write) does not
help — the block is content-based, not path- or process-based, and a write can
report success while the file stays unreadable. `ls -l@` shows a
`com.apple.provenance` xattr; that is a red herring (readable files have it too and
`xattr -c` cannot clear it).

Other PoC URLs worth having:

| CVE | Source |
|---|---|
| CVE-2021-1675 | `cube0x0/CVE-2021-1675` — `SharpPrintNightmare/CVE-2021-1675.py` (blocked, see above) |
| CVE-2023-23397 | `vlad-a-man/CVE-2023-23397` — `lol.py` (in tree) |
| CVE-2023-40044 | KittySploit WS_FTP module (in tree) |

The remaining 42 PoC sources are listed per-CVE in
`3-trace-align/splunk_extend/RESULTS.md`.

## Open work — the compile→align gap

**This is the main thing left.** `compile_pocs.py` produces 42 templates, but only
**21 of 42** align against their own provenance graph under the default matcher
(33/42 with `TRACE_ALIGN_RW_INTERCHANGE=1`). The shipped 45/45 comes from the
*shipped* templates in `splunk_extend/graphs` and `poc_graphs/graphs`, not from
compiler output. The README does not claim otherwise — keep it that way unless the
gap closes.

Diagnosed causes, from comparing compiled vs shipped templates on the 21 failures:

1. **Locus mismatch (largest group).** The shipped template is runner-side
   (local locus: the PoC's own process, file drops, spawn chains) while
   `_detect_locus` infers remote and emits the target view
   (`net_client -> proc_host -> resource`). Affects at least CVE-2017-0199,
   CVE-2021-29995, CVE-2022-25237, CVE-2023-22855, CVE-2023-23488.
2. **Label over-specificity.** Compiled labels carry the full query string where
   the provenance records only the path — e.g. CVE-2023-24489 compiles
   `*/documentum/upload.aspx?parentid=*&raw=1&unzip=on&...` where the shipped
   template is `*/documentum/upload.aspx*`.
3. **Event-class verb.** e.g. CVE-2022-1388 compiles the resource edge as `write`
   where the provenance records `read`.

Untried and promising: stage 2 emits a *family* of path variants per PoC and
`compile_pocs.py` keeps only the richest by edge count. The paper's wider grade
counts a CVE if **any** family member satisfies the alert predicate, so evaluating
every variant (and both loci) rather than one per CVE is both more faithful and
likely to close part of the gap. A harness for this was started but not finished.

## Changes made in this session

**Stage 2 — CVE-2021-1675 now compiles from the real PoC.** Its template was
hand-authored before; it is now compiler output from the unmodified cube0x0 PoC,
and it aligns. Three changes were needed:

- `syscall_mapping.json`: added the MS-RPRN/MS-PAR print-spooler RPC family
  (`hept_map` → net connect; `hRpcAsyncAddPrinterDriver` / `hRpcAddPrinterDriverEx`
  → target-side file write). Listed under both the import-alias and
  module-qualified key forms, because `sanitize_poc.py` sees source-level dotted
  names while `convert_graph.py` sees import-resolved ones. 88 → 94 identifiers.
- `convert_graph.py`: track literals assigned into a struct field-by-field (the
  operand is fixed in the subscript assignment, not at the call site); fold
  `str.format()` keeping the fixed prefix, matching the `%` and f-string branches
  already there; strip the wire NUL terminator.
- `sanitize_poc.py`: `--keep-call-chain`, **off by default**, used by
  `compile_pocs.py` as a second attempt only when the first yields no template.
  Needed because cube0x0 drives the exploit through helpers from `__main__`, so
  anchor-only pruning leaves them unreachable.

Verified no regression: recompiled all PoCs against a pre-change baseline —
31 identical, 12 changed, 0 lost, 0 gained. The 12 changes are the pre-existing
uncommitted `| */<service>/*` alternative, not from this work.

**Stage 3 — mass floor added.** `design.tex` states the alert predicate is
`MS >= tau` **and** `sum w_i n_i >= w_3`. The code computed the mass term and
discarded it, checking only `MS >= tau`. Now both. Costs nothing: 45/45 and
0 false alerts unchanged.

**Stage 3 — read/write interchange is now opt-in.** `_sc_eq` treated `read` and
`write` as one class unconditionally (added in commit `a251a0c`). That is a
relaxation, and it was the entire source of a 4-false-alert discrepancy against the
reported `0 of 1056`. It is now behind `TRACE_ALIGN_RW_INTERCHANGE`, default off,
which reproduces the reported numbers exactly.

## Findings worth not rediscovering

**The 4 "false positives" were not a bug and not a data error.**
`prov-CVE-2023-4966.txt:27` genuinely contains `/?PHPRC=/dev/fd/0` — that capture is
a broad scanner trace (170 nodes, Assetnote UA) that includes a real Juniper
CVE-2023-36844 probe. The Juniper captures record that access as `read`; prov-4966
records it as `write`. With exact event-class equality the templates do not
cross-match; only the read/write relaxation made them. Node has been in the file
since the initial commit, so nothing drifted.

**The matcher is not loose in general.** Of 15 templates with any label match
against prov-4966, only those with a genuinely discriminative anchor align; the rest
match only on trailing `|*` wildcards and are correctly rejected.

**Paper-fidelity deviations still open** (measured, not guessed):

- Π is 94 identifiers / 26 families / 0 collector profiles; the paper states
  312 / 28 / 6.
- No temporal model at all. The paper specifies Δ=15 min windows, ε=2 s clock skew
  and ordering read from `t(mu_E(e))`; the graph format carries no timestamps, so
  ordering and window constraints are absent.
- Path refinement is more permissive than specified. The paper requires the terminal
  edge be class σ with *every preceding edge a process creation*;
  `_find_k_tolerant_path` accepts σ anywhere on the path with any intermediate
  class, and does not enforce that distinct template edges take distinct terminal
  occurrences. **Implementing the paper's rule faithfully drops CVE-2023-29357 to
  32/33** — its provenance records `/_api/web/siteusers` under `proc_example_com_4`
  and `/_layouts/15/spinstall0.aspx` under `proc_sharepoint_example_com_8`, two
  process vertices for what the template treats as one server. The loose rule
  bridges them by walking network hops between hosts. Left unchanged: this is a
  provenance-graph question, not a matcher one, and it changes a verified result.
- Π's freeze claim ("0 identifiers added after 1 March 2024") and the Π manifest
  SHA-256 are now stale, since this session added the print-spooler RPC family.

**Parameters that do match the paper:** τ=0.43, weights (0.20, 0.33, 0.47), k=3,
h=3, and the C1/C2/C3 definitions.

**Expected non-failures.** Four shipped PoCs (CVE-2018-8174, CVE-2023-29298,
CVE-2024-25600, CVE-2025-31324) fail a bare `ast.parse` because they are Python 2 /
pre-3.10 source. That is handled by `sanitize_poc.py`'s `_py2_to_py3` and
`_lower_py310_syntax` fallbacks and is not a problem. CVE-2017-11882 produces no
template (document generator, no log-evident anchor) and did so before any of this
session's changes; CVE-2023-23397 sanitizes to zero bytes because `win32com` is not
in Π and `ReminderSoundFile = ...` is a property assignment rather than a call.
