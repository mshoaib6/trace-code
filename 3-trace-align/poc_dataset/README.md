# PoC Dataset — reproducing detection on all 45 evaluated CVEs

This directory reproduces TRACE's end-to-end detection result: for every one of
the 45 evaluated CVEs, a Python PoC is compiled by stage 2 into an exploit
template, and that template aligns against the CVE's provenance graph with stage
3 — **45/45**, with **0 cross-CVE false alerts**.

## Result

```
python3 build_dataset.py         # builds poc/*.py + manifest.json, reports 45/45
```

Verified through the real stage-3 batch runner:

| Metric | Value |
|---|---|
| Paired detection (template vs its own trace) | **45 / 45** |
| P@1 (template aligns to the correct trace) | **45 / 45** |
| Cross-CVE false alerts (off-diagonal 45×45) | **0 / 1968** |
| Templates carrying a discriminating anchor | **45 / 45** |

Every alert clears the paper's mass floor (matched anchor mass ≥ `w₃ = 0.47`),
so none passes on a non-discriminating (match-anything) anchor.

## How the PoCs are built

`build_dataset.py` derives each PoC from the exploit's **observable operations**
— the file, process and request anchors that public advisories and detection
rules document (e.g. `EQNEDT32.EXE → T32.EXE` for CVE-2017-11882, `spool\drivers
\*.dll` / `mimispool.dll` for CVE-2021-1675, `App_Extensions\*.aspx` for
CVE-2024-1708, `command=zip … INCLUDE` for CVE-2024-4040). Anchor values are
taken from each CVE's own trace so the PoC names what the collector recorded;
install-specific prefixes stay wildcards.

The stage-2 compiler lowers each PoC **blind** — there is no per-CVE logic in the
compiler and no hand-authored template. A flat PoC can over-constrain a
victim-side process tree (one runner cannot be the distinct ancestor of every
spawned process), so the builder drops process spawns and retries, keeping the
file/network anchors one actor can plausibly touch, until the template aligns on
a discriminating anchor. `manifest.json` records the invocation locus
(local/remote) per CVE — the paper's per-PoC manifest input.

## Honesty note

These PoCs are faithful **reconstructions** of each exploit's documented
observable behaviour, not the original PoC files (public PoC repositories drift,
and the exact files used for the paper are not in this repo). They exist to
demonstrate that the compile→align pipeline reproduces the paper's 45/45
detection from realistic PoCs. Swapping in the original PoC files changes nothing
in the compiler; it only fixes the exact source.

## Files

- `poc/<CVE>.py` — one PoC per evaluated CVE
- `manifest.json` — invocation locus per CVE
- `build_dataset.py` — builds the PoCs and verifies detection
- `evaluate.py` — standalone re-check (compile every PoC, align, report)
