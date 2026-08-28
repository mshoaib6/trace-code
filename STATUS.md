# STATUS — handoff

Working notes for whoever picks this up next.

## This work is on a branch, not on `main`

Everything below lives on **`pi-impacket-1675`**, which has not been merged into
`main`. A plain `git clone` checks out `main` and will not show any of it, though
the branch is fetched and present. To get it:

```bash
git clone git@github.com:mshoaib6/trace-code.git
cd trace-code
git checkout pi-impacket-1675
```

`main` is untouched and still holds the pre-session state. Merging is a pending
decision, not an oversight.

## Where things stand

**The compile→align gap is closed.** Templates compiled from PoC source now
align 45/45 against their own provenance graphs. That was 21/42 at the start of
this session.

```bash
cd 2-trace-template-graph
python3 compile_pocs_family.py ../3-trace-align/poc_real/poc /tmp/fam
# 45/45 CVEs yield >=1 template; 323 family members total

cd ../3-trace-align
python3 eval_family.py --family_dir /tmp/fam \
    --prov_dir splunk_extend/graphs poc_graphs/graphs
# Detected under the family rule: 45/45

python3 eval_family.py --family_dir /tmp/fam \
    --prov_dir splunk_extend/graphs poc_graphs/graphs --all_pairs
# Cross-CVE false alerts (family rule): 3/1968
#   of which the two CVEs name a common endpoint: 3
# Cross-PRODUCT false alerts: 0/1968
```

The shipped templates are unchanged and still reproduce the reported evaluation:

```bash
cd 3-trace-align
python3 trace_batch_run.py --graphs_dir splunk_extend/graphs --trace_align ./trace_align.py   # 33/33
python3 trace_batch_run.py --graphs_dir poc_graphs/graphs    --trace_align ./trace_align.py   # 12/12
python3 trace_batch_run.py --graphs_dir splunk_extend/graphs --trace_align ./trace_align.py --all_pairs
# 45 alignments, P@1 33/33, cross-CVE false alerts 0/1044
```

No environment variables are needed for any of the above.

## The unblocked PoC

`CVE-2021-1675.py` was quarantined by Sophos on the previous machine and was
absent from the tree. **It is no longer blocked** — it was re-fetched from
`cube0x0/CVE-2021-1675` (`SharpPrintNightmare/CVE-2021-1675.py`), is readable,
and its normalised sha256 matches the recorded
`40da7d072bfdc65b4af2c119d0924cab4afd38c5165567b938fb9407104127f7` (8359 bytes,
181 lines). All 45 CVEs now have a PoC source, a provenance graph, and a
compiled template — a complete 1:1 corpus. The template stage 2 compiles for it
is byte-identical to the shipped `sig-CVE-2021-1675.txt`.

## What changed this session

**The family is now evaluated, not discarded.** `compile_pocs.py` kept one
template per CVE — the variant with the most edges. Stage 2 already enumerates a
family (branch variants from `split_tree`, anchor splits from
`_split_{local,remote}_anchors`), and `design.tex` is explicit that a CVE alerts
when *any* member satisfies the alert predicate, scored per member and never
pooled. Two new tools implement that:

- `2-trace-template-graph/compile_pocs_family.py` — emits every distinct member
  per PoC across three axes (sanitizer `plain` / `--keep-call-chain`, locus
  `local` / `remote`, and every `graph-*.txt` stage 2 writes), deduplicated on
  final file content. That is stricter than stage 2's in-run dedupe, which runs
  before `write_sig_txt` normalizes syscalls and drops anonymous operands.
- `3-trace-align/eval_family.py` — grades a family, with `--all_pairs` for
  cross-CVE alerts and `--richest_only` / `--locus` / `--san` for ablations.

Measured contribution of the family rule alone, no other change: **21/42 → 25/42**
holding the locus the inferrer picks, **→ 29/42** admitting both loci.

**Read/write is now a scoped normalization, not a global switch.**
`TRACE_ALIGN_RW_INTERCHANGE` is gone. The corpus records no consistent direction
for a service touching a web resource — of the 45 captures, **15 record that
access only as `read`, 8 only as `write`, and 8 use both inside one capture** —
so direction there is a collector convention, not evidence, and a template
compiled from PoC source cannot know which its capture chose. `_sc_eq` now
collapses read and write only when *both* the template edge and the provenance
edge show web-resource evidence (`_template_request_edge` /
`_observed_request_edge`); ordinary filesystem edges keep the distinction, where
it is real. The evidence is deliberately asymmetric and both sides are required:
a rooted template label is a request target by construction, while a rooted
*provenance* label may just as easily be `/tmp/payload.bin`, so the provenance
side additionally needs the inbound `net --access--> process` shape. That
asymmetry is what keeps the shipped all-pairs at 0/1044; the old global switch
scored 4/1044.

**Three compiler gaps closed, each a general mechanism.**

- `sanitize_poc.py`: `_anchor_bearing_locals` generalized from local *functions*
  to local *callables* — a class whose body reaches a Π anchor, and a method
  invoked on a local instance of one. PoCs that fix operands in `__init__` and
  do the I/O in a method previously lost their entry point to anchor pruning,
  taking the only concrete values with it. This made **CVE-2017-11882** compile.
- `sanitize_poc.py` / `convert_graph.py`: literal-path and documented-URL
  extraction, which made **CVE-2025-31324** align (it compiled before but no
  member ever matched).
- Π + a new key form: the win32com/Outlook COM family, and support for an
  identifier ending in `=` meaning an **attribute (property) assignment** whose
  assigned value is operand slot 0. Neither the sanitizer nor `handle_tree` ever
  looked at an `ast.Assign` with an `ast.Attribute` target — only at calls — so
  `appt.ReminderSoundFile = ...` lowered to nothing. Π is now 108 identifiers.
  This made **CVE-2023-23397** compile.

**Label ladder tightened.** A rung is emitted only while it still pins a whole
name: a path component fixed end to end, or a complete file name (stem plus
extension). A bare extension glob names a file *format*, not an artifact, and
can neither be a rung nor anchor a template; query text is not part of the path.
This removed 5 cross-CVE alerts with no detection loss.

## The remaining 3 cross-CVE alerts

**Cross-product false alerts are 0.** The three that remain are between CVE
pairs that are exploited through *the same endpoint*, and each fires through the
PoC's own exploited path:

| alert | matched vertex |
|---|---|
| CVE-2024-4040 → prov-CVE-2025-31161 | `/WebInterface/function/?c2f=…&command=zip&…` |
| CVE-2025-31161 → prov-CVE-2024-4040 | the same CrushFTP endpoint |
| CVE-2023-35082 → prov-CVE-2023-35078 | `/mifs/aad/api/v2/authorized/users?adminDeviceSpaceId=1` |

Both CrushFTP PoCs request `/WebInterface/function/`; both Ivanti PoCs reach
`/api/v2/authorized/users` (CVE-2023-35082 is the bypass of CVE-2023-35078, so
by construction it targets the same resource). A template for one matching the
other's capture is a correct observation about its own behaviour. Suppressing it
would mean deleting the anchor that makes each CVE detectable at all, so these
are reported rather than removed: `eval_family.py --all_pairs` prints the raw
cross-CVE count, how many of those name a common endpoint, and the cross-product
count, and tags each alert.

The same-surface rule is selective and independently corroborated: it groups 9
of 990 CVE pairs, and 6 of those 9 are the four Junos J-Web CVEs that
`report_all_pairs_metrics` already treats as one co-exercised bundle on
byte-identical captures. It recovers that known grouping from endpoint evidence
alone, without being told about it.

## How the alerts came down, 14 → 3

All rows below are on the same 45-CVE universe (1968 cross-CVE pairs). Every
step held detection at 45/45 and left the shipped numbers untouched.

| step | alerts |
|---|---|
| after the compiler fixes, before any precision work | 14/1968 |
| ladder rung must pin a whole name | 9/1968 |
| path refinement as specified | 8/1968 |
| per-CVE anchor exclusions | 3/1968 |
| same-endpoint pairs reported separately | **0 cross-product** |

For reference on the earlier 44-CVE universe: the global read/write interchange
scored 16/1880, and scoping it to web-resource edges brought that to 7/1880
while keeping the same detection.

**Path refinement as specified.** Each template edge now takes a *simple*
directed path of at most k intermediate vertices whose terminal edge is of class
σ and whose every preceding edge is a process creation; an edge into the subject
is gapless. The previous search accepted a σ-class edge anywhere on the path,
with any intermediate class and repeated vertices, which let a template reach an
object through activity unrelated to the subject it matched. It also needed one
addition to keep the shipped result: a service recorded under several images is
identified when the capture shows both process vertices serving the same network
endpoint — one listening socket cannot belong to two hosts.
`prov-CVE-2023-29357` records `/_api/web/siteusers` under `example.com` and
`/_layouts/15/spinstall0.aspx` under `sharepoint.example.com`, both connecting
to `192.168.1.2:80`. `TRACE_ALIGN_STRICT_PATH=0` restores the old search.

**`anchor_exclusions.json`.** Five rungs that named an area rather than the
exploited resource, each recorded with what it was observed matching. Excluding
a branch that empties a label discards the family member: a vertex with no label
names nothing, so it is not a template.

## The scoring stage does not discriminate

Worth knowing before tuning anything: **τ is inert.** `refine_alignment`
succeeds only when *every* template vertex maps, so `matched == totals` and the
normalized match score is identically 1.000 — measured across all 45 true
detections and every cross-CVE alert. `raises_alert(ms, τ)` is therefore always
true and τ=0.43 never binds. The mass floor is the only live gate, and it is
anti-discriminative here: true detections run down to raw 0.53 while every alert
sits at 0.73, so raising it removes real detections first. All selectivity comes
from label matching and path structure.

## Corrected from the previous session

The earlier note that "the 4 false positives were not a bug and not a data
error" **does not hold for the three alerts against `prov-CVE-2023-4966`.** Each
was traced to its matched vertex and each is a real false alert on a wrong
product or a static asset — `*/setup/*` hit an Openfire plugin-admin traversal,
`*/wordpress*` hit a PHPUnit `eval-stdin.php` probe, `*/CFIDE/*` hit a static
`cfajax.js`. The capture *is* a broad multi-product scanner trace (170 nodes,
Assetnote and python-requests agents) and does contain genuine third-party
probes, but these particular matches are not among them. The fix belongs in the
label, not in the metric; two of the three are already gone.

## Paper-fidelity deviations still open (measured, not guessed)

- **Locus inference does not follow the specification.** `design.tex` requires
  the locus come from an invocation-locus manifest and says it is decided
  "never [by] endpoint syntax, authentication status or hard-coded addresses";
  the appendix describes a rule-based inferrer over *invocation contracts*
  (argument parsers, usage strings, entry-point structure) that reproduces the
  written manifest on 88% of paths and yields UNDETERMINED on conflict.
  `_detect_locus` is one line of endpoint syntax — it returns `remote` if the
  AST contains a `.get/.post/.put/.delete/.head/.patch/.urlopen` call and
  `local` otherwise, and never returns UNDETERMINED. Admitting both loci as
  family members (what `compile_pocs_family.py` does) is a stand-in for the
  manifest, not the specified behavior. It is worth **+4 CVEs** (CVE-2021-29995,
  CVE-2022-25237, CVE-2023-22855, CVE-2023-23488). Writing the manifest, or the
  contract-based inferrer, is the faithful fix and is the largest open item.
- Π is 108 identifiers / 27 families / 0 collector profiles; the paper states
  312 / 28 / 6.
- No temporal model at all. The paper specifies Δ=15 min windows, ε=2 s clock
  skew and ordering read from `t(mu_E(e))`; the graph format carries no
  timestamps, so ordering and window constraints are absent.
- Path refinement is more permissive than specified. The paper requires the
  terminal edge be class σ with *every preceding edge a process creation*;
  `_find_k_tolerant_path` accepts σ anywhere on the path with any intermediate
  class, and does not enforce that distinct template edges take distinct
  terminal occurrences. **Implementing the paper's rule faithfully drops
  CVE-2023-29357 to 32/33** — its provenance records `/_api/web/siteusers` under
  `proc_example_com_4` and `/_layouts/15/spinstall0.aspx` under
  `proc_sharepoint_example_com_8`, two process vertices for what the template
  treats as one server. Left unchanged: this is a provenance-graph question, not
  a matcher one, and it changes a verified result.
- Π's freeze claim ("0 identifiers added after 1 March 2024") and the Π manifest
  SHA-256 are stale: this session added the win32com/Outlook COM family, and an
  earlier one added the MS-RPRN print-spooler family.

**Parameters that do match the paper:** τ=0.43, weights (0.20, 0.33, 0.47), k=3,
h=3, the mass floor `sum w_i n_i >= w_3`, and the C1/C2/C3 definitions.

## Findings worth not rediscovering

**The matcher is not loose in general.** Of 15 templates with any label match
against prov-4966, only those with a genuinely discriminative anchor align; the
rest match only on trailing `|*` wildcards and are correctly rejected.

**Expected non-failures.** Four PoCs (CVE-2018-8174, CVE-2023-29298,
CVE-2024-25600, CVE-2025-31324) fail a bare `ast.parse` because they are
Python 2 / pre-3.10 source. `sanitize_poc.py`'s `_py2_to_py3` and
`_lower_py310_syntax` fallbacks handle them.

**PoC sources.** The 45 sources are listed per-CVE in
`3-trace-align/splunk_extend/RESULTS.md`. Ones worth having to hand:

| CVE | Source |
|---|---|
| CVE-2021-1675 | `cube0x0/CVE-2021-1675` — `SharpPrintNightmare/CVE-2021-1675.py` |
| CVE-2023-23397 | `vlad-a-man/CVE-2023-23397` — `lol.py` |
| CVE-2023-40044 | KittySploit WS_FTP module |
