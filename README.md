# Lab 15: Automation

A reconnaissance and log-analysis toolkit in Python: a concurrent port scanner, an nmap XML parser,
log analyzers with anomaly detection, and an integrated reconnaissance tool with an audit log.
Completed in pairs by **Sebastian Albarracin Silva** (scanner engineer) and **Juan Rodriguez** (log analyst).

## Requirements
- Kali Linux (VMware VM), **Python 3.14.7** (3.10 or newer is required).
- **Python standard library only: no pip dependencies are needed.**
- System tools: `nmap`, `ssh-keyscan`, `whois`, `dig`, `curl`, `git`
  (`sudo apt install nmap whois bind9-dnsutils openssh-client curl git`).
- The only authorized target is `192.168.216.128` (see `scope.txt`). The domain-mode test target is
  `example.com` (reserved for documentation, RFC 2606).

## Scripts

| Script | Part | What it does | Example |
|---|---|---|---|
| `plant_logs.py` | 0 | Plants attacks into the Moodle base logs and writes `planted.json` | `python3 plant_logs.py` |
| `scanner_seq.py` | 1A | Sequential reference scanner (from the lab guide) | `python3 scanner_seq.py` |
| `bench_threads.py` | 1A | Benchmarks `ThreadPoolExecutor` with 50/200/500 workers | `python3 bench_threads.py` |
| `scanner.py` | 1B-D | asyncio + Semaphore scanner with CLI and JSON output | `python3 scanner.py 192.168.216.128 --ports 1-1024 --rate 200 --output scan_rate200.json` |
| `parse_scan.py` | 2 | Parses nmap XML and adds the SSH host key types | `python3 parse_scan.py --input scan.xml --output hosts.json` |
| `auth_analysis.py` | 3A | SSH brute force, targeted accounts, failure ratio, success after failures | `python3 auth_analysis.py auth.log` |
| `log_analysis.py` | 3B-D | Web attacks, top 5 IPs, HTTP status codes and 3-sigma anomalies | `python3 log_analysis.py access.log` |
| `make_report.py` | 3E | Combines 3A-3D into `report.md` | `python3 make_report.py --auth auth.log --access access.log` |
| `score_findings.py` | 3 | Compares `planted.json` with the detections and writes `findings_score.md` | `python3 score_findings.py` |
| `recon.py` | 4 | Domain or IP reconnaissance producing `results.json`, `report.md` and `audit.log` | `python3 recon.py example.com --verbose` |

## Design choices
- **Classified outcomes, not collapsed ones (`scanner.py`).** Every port ends as `open`, `closed`
  (a RST came back), `filtered` (timeout) or `error:<errno>`. An error is never reported as "closed": at
  `--rate 2000` there were 6 EMFILE errors (errno 24, `ulimit -n` = 1024); the JSON lists them and the program
  exits with code 2 so that an incomplete result cannot pass as a complete one.
- **asyncio + Semaphore.** Caps concurrent connections without creating operating-system threads; the
  optional `--jitter` breaks the regular timing between probes.
- **XML parsing with `xml.etree`.** The address is selected by `addrtype` (not the first `<address>`, which
  may be the MAC); `hostname` may be `null`; `ssh_host_key_type` is a list because the server presents
  several keys (including `ssh-mldsa44-ed25519`, a post-quantum key from OpenSSH 10.6).
- **Robust log regexes.** `invalid user` is optional (the theory pattern missed 63 failures); request paths
  are decoded up to 3 times (double encoding), SQL comments `/**/` are stripped and everything is lowercased;
  the log path may contain spaces; hours with no traffic count as 0 for the 3-sigma baseline.
- **`recon.py`.** Every external call goes through `run_logged()` (complete audit log) and every stage runs
  inside `run_stage()`, which catches any exception so a failing stage never stops the others.
  `results.json` holds only structured fields, never raw tool output.
- **Minimal privilege.** No script needs root: the scanner uses a connect scan and nmap runs without sudo.
  Only the Part 0 test listeners used sudo, because they listen on ports below 1024.

## Main results
- Part 1: the 4 expected ports (22, 210, 555, 888) were found at every rate; at rate 2000, 6 ports were left
  without a result because of EMFILE. See `notes/part1.md`.
- Part 2: `nmap` without `-p` did not report port 210 (it is not among the default 1000 ports); with
  `-p 1-1024` all 4 appeared. See `notes/part2.md`.
- Part 3: 12/12 planted items detected and 0 false positives; first-draft misses and their fixes are in
  `findings_score.md`. See `notes/part3.md`.
- Part 4: runs in `sample_output/ip`, `sample_output/domain` and `sample_output/failure_test`
  (no tools on PATH, to show that each stage fails independently). See `notes/part4.md`.

The answers to each part's question are in `notes/`.

## Who did what

| Role | Person | Deliverables |
|---|---|---|
| Scanner engineer | Sebastian Albarracin Silva | `plant_logs.py`, `planted.json`, `scanner_seq.py`, `bench_threads.py`, `scanner.py`, `scan_rate200.json`, `scan_rate2000.json`, `parse_scan.py`, `scan.xml`, `hosts.json`, `score_findings.py`, `findings_score.md`, `recon.py` stages (requirements 1, 3 and 4: CLI, whois, dig, curl, nmap), final merge of `recon.py` and audit log verification, answers to the Part 1 and Part 2 questions |
| Log analyst | Juan Rodriguez | `scope.txt`, target preparation (listeners on ports 210/555/888 + SSH) and answer key, `auth_analysis.py`, `log_analysis.py`, `make_report.py`, `report.md`, `run_logged()` and audit log, `results.json` assembly and `report.md` generation in `recon.py` (requirements 2, 5 and 6), Part 1 confirmation of missed ports, answers to the Part 3 and Part 4 questions |

Handoff files that crossed between the roles:

| # | Direction | Files |
|---|---|---|
| 1 | Analyst -> Engineer | `scope.txt` |
| 2 | Engineer -> Analyst | planted `auth.log` and `access.log` (the analyst never saw the base logs or `planted.json`) |
| 3 | Engineer -> Analyst | `scan_rate200.json`, `scan_rate2000.json` |
| 4 | Analyst -> Engineer | `report.md` (scored into `findings_score.md`) |
| 5 | Analyst -> Engineer | `run_logged()` |
| 6 | Engineer -> Analyst | `results.json` from a recon run in IP mode |

Questions: Part 1 answered by the engineer with the analyst's confirmation; Part 2 by the engineer; Part 3 by
the analyst, reviewed by the engineer; Part 4 by the analyst (not the author of the final merge), reviewed by
the engineer.
