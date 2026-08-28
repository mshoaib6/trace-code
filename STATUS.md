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
# Cross-CVE false alerts (family rule): 9/1968
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

## Open — the 9 remaining cross-CVE alerts

Every one was traced to its matched provenance vertex. They are two different
things and only one is a defect:

**Genuinely the same exploited endpoint (4).** Not detector errors — the two
CVEs really do target the same resource, so a template for one legitimately
matches the other's traffic:

| alert | matched vertex |
|---|---|
| CVE-2023-35082 → prov-CVE-2023-35078 | `/mifs/aad/api/v2/authorized/users?adminDeviceSpaceId=1` |
| CVE-2024-1708 → prov-CVE-2024-1709 | `/SetupWizard.aspx/eXjZELemBx` — the 1708 PoC performs the 1709 bypass itself |
| CVE-2024-4040 → prov-CVE-2025-31161 | `/WebInterface/login.html` |
| CVE-2025-31161 → prov-CVE-2024-4040 | `/WebInterface/function/?c2f=…&command=zip&…` — both CrushFTP PoCs request it |

Treating these as false alerts is arguably a metric error. `report_all_pairs_metrics`
already excludes pairs drawn from one co-exercised bundle (the four Junos J-Web
CVEs). The grouping is currently keyed on byte-identical captures; these pairs
are *not* byte-identical — that was measured across all 990 capture pairs on
vertex/edge Jaccard, shared endpoints and containment, and the hypothesis was
rejected — so extending the rule would have to key on the shared endpoint
instead, which is a deliberate metric decision and has not been taken.

**Site-root rung reaching another product (4).** The coarsest rung the compiler
emits, `*/<first-segment>/*`:

| alert | matched vertex | verdict |
|---|---|---|
| CVE-2023-22515 → prov-CVE-2023-4966 | `/setup/setup-s/%u002e%u002e/%u002e%u002e/plugin-admin.jsp` | wrong product — an Openfire traversal |
| CVE-2023-22515 → prov-CVE-2024-21683 | `/setup/finishsetup.action?-` | same product, different setup endpoint |
| CVE-2023-29298 → prov-CVE-2023-4966 | `/CFIDE/scripts/ajax/package/cfajax.js` | static asset, not the admin endpoint |
| CVE-2023-35078 → prov-CVE-2023-35082 | `/mifs/asfV3/api/v2/authorized/users` | same Ivanti endpoint family |

**Deleting the site-root rung was tried and reverted.** It drops these to 5
alerts total but costs **CVE-2023-40044**, whose PoC probes
`/AHT/AHT_UI/public/js/app.min.js` as a version check while its capture recorded
the exploited `/AHT/AhtApiService.asmx/AuthUser` — a different resource under the
same root, which only that rung bridges. The rung that rescues CVE-2023-40044 is
the same one that lets `*/setup/*` reach an Openfire page. That is the real
frontier, and it is a genuine precision/recall tradeoff, not a bug:

| configuration | detection | compiled cross-CVE alerts |
|---|---|---|
| site-root rung kept (current) | **45/45** | 9/1968 |
| site-root rung removed | 44/45 | 5/1968 |

A rule that separates the two would have to distinguish a coarse rung matching a
*static asset* (`cfajax.js`, `login.html`) from one matching an *API endpoint*
(`AhtApiService.asmx/AuthUser`). That is plausible and untried.

**One alert is a vacuous template.** `CVE-2023-23397 → prov-CVE-2021-1675` fires
through `svchost.exe --connect--> *`, true on any Windows host. It is also the
*only* member that "detects" CVE-2023-23397, so rejecting it would drop detection
to 44/45. That is not a compiler defect:
`prov-CVE-2023-23397.txt` contains **no file artifacts at all** — only a
post-exploitation process chain (svchost→rundll32, powershell→cmd→rundll32, and
a connection out on :443). The PoC sets an Outlook `ReminderSoundFile` to a UNC
path; the capture records the payload execution that follows. They describe
different phases of the attack, so no compiler can derive one from the other —
the shipped template for this CVE was authored from the capture. **Read 45/45 as
44 genuine plus one that rests on a non-discriminating anchor.**

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
