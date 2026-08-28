# Splunk attack_data Results

33 CVEs from the Splunk `attack_data` corpus (`attack_techniques/T1190/*.yml`, plus one Sysmon dataset under `T1505.003`), spanning 23 products, 5 collector formats, and 2021–2025. Provenance graphs are parsed from each CVE's own Splunk dataset; template graphs come from each CVE's public Python PoC.

## Results

| Metric | Value |
|---|---|
| CVEs evaluated | 33 |
| Paired alignment | 33 / 33 |
| P@1 in the 33×33 matrix | 33 / 33 |
| Cross-CVE false alerts | 0 of 1056 |
| Alignments in the 33×33 matrix | 45 |

The 45 alignments are the 33 diagonal pairs plus 12 inside the Juniper chain, which `juniper.yml` publishes as a single capture (`suricata_junos_cvemegazord.log`) covering all four of its CVEs.

False positives are measured on the SOCBED benign corpus, which is not shipped here.

## Per-Bundle Breakdown

| Bundle | Products | CVEs | Years | Log sources | TP | P@1 |
|---|---|---|---|---|---|---|
| `juniper.yml` | Junos J-Web | 4 | 2023 | Suricata | 4 / 4 | 4 / 4 |
| `ivanti.yml` | EPMM, Sentry, VTM | 4 | 2023–24 | Suricata, Nginx | 4 / 4 | 4 / 4 |
| `confluence.yml` | Confluence | 3 | 2023–24 | Nginx, Suricata | 3 / 3 | 3 / 3 |
| `citrix.yml` | NetScaler ADC/Gateway | 3 | 2023–25 | Nginx, Suricata | 3 / 3 | 3 / 3 |
| `screenconnect.yml` | ScreenConnect | 2 | 2024 | Sysmon, Suricata | 2 / 2 | 2 / 2 |
| `crushftp.yml` | CrushFTP | 2 | 2024–25 | CrushFTP, Sysmon | 2 / 2 | 2 / 2 |
| 15 singletons | 15 products | 15 | 2021–25 | Sysmon, Suricata, Nginx, Palo Alto | 15 / 15 | 15 / 15 |
| **Σ** | **23 products** | **33** | **2021–25** | **5 formats** | **33 / 33** | **33 / 33** |

## Scope

Every evaluated CVE is log-evident and has a public Python PoC. Two CVEs from the initial 35-CVE pull are excluded: CVE-2023-26460, whose Splunk log content is ColdFusion traffic under an SAP label, and CVE-2023-29360, a kernel elevation-of-privilege issue that produces no log-evident behavior.

| CVE | Public Python PoC |
|---|---|
| CVE-2021-1675 | cube0x0/CVE-2021-1675 |
| CVE-2022-1388 | horizon3ai/CVE-2022-1388 |
| CVE-2022-22965 | reznok/Spring4Shell-POC |
| CVE-2022-40684 | horizon3ai/CVE-2022-40684 |
| CVE-2022-42889 | kljunowsky/CVE-2022-42889-text4shell |
| CVE-2023-20198 | smokeintheshell/CVE-2023-20198 |
| CVE-2023-22515 | Chocapikk/CVE-2023-22515 |
| CVE-2023-22527 | Avento/CVE-2023-22527_Confluence_RCE |
| CVE-2023-23397 | vlad-a-man/CVE-2023-23397 |
| CVE-2023-24489 | adhikara13/CVE-2023-24489-ShareFile |
| CVE-2023-29298 | Rapid7 + jakabakos chain (with CVE-2023-26360) |
| CVE-2023-29357 | Chocapikk/CVE-2023-29357 |
| CVE-2023-35078 | vchan-in/CVE-2023-35078-Exploit-POC |
| CVE-2023-35081 | chained with 35078; Horizon3 advisory |
| CVE-2023-35082 | Rapid7 / Horizon3 disclosures |
| CVE-2023-3519 | BishopFox/CVE-2023-3519 |
| CVE-2023-36844 | watchtowrlabs/juniper-rce_cve-2023-36844 |
| CVE-2023-36845 | same repo |
| CVE-2023-36846 | same repo |
| CVE-2023-36847 | same repo |
| CVE-2023-4966 | Assetnote citrix-bleed-scanner |
| CVE-2023-40044 | Rapid7 MSF module and public Python PoCs |
| CVE-2024-1708 | Teexo/ScreenConnect-CVE-2024-1709-Exploit |
| CVE-2024-1709 | W01fh4cker/ScreenConnect-AuthBypass-RCE |
| CVE-2024-21683 | SammyEnigma/CVE-2024-21683 |
| CVE-2024-23897 | CKevens/CVE-2024-23897 |
| CVE-2024-25600 | Chocapikk/CVE-2024-25600 |
| CVE-2024-4040 | Airbus-CERT/CVE-2024-4040 |
| CVE-2024-5806 | watchtowrlabs/watchTowr-vs-progress-moveit_CVE-2024-5806 |
| CVE-2024-7593 | D3N14LD15K/CVE-2024-7593_PoC_Exploit |
| CVE-2025-31161 | 0xgh057r3c0n/CVE-2025-31161 |
| CVE-2025-31324 | Alizngnc/SAP-CVE-2025-31324 |
| CVE-2025-5777 | bughuntar/CVE-2025-5777 |

## Reproduce

Compile the templates from the public PoCs (stage 2), then align them against the
Splunk-derived provenance graphs (stage 3):

```bash
cd code/2-trace-template-graph
python compile_pocs.py ../3-trace-align/poc_real/poc sig_out

cd ../3-trace-align
python trace_batch_run.py --graphs_dir splunk_extend/graphs --trace_align ./trace_align.py
python trace_batch_run.py --graphs_dir splunk_extend/graphs --trace_align ./trace_align.py --all_pairs
```

Results are written to `output.txt` and `output-all_pairs.txt`.
