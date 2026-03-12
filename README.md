# HPE iLO automation scripts

Production-ready Python scripts for HPE iLO Redfish: inventory collection and BIOS configuration (Nutanix-oriented profiles, Secure Boot, certificate enrollment).

## Contents

- [Scripts](#scripts)
- [Requirements](#requirements)
- [Configuration](#configuration)
- [BIOS profiles](#bios-profiles)
- [Quick start](#quick-start)
- [HPE_set_bios.py options](#hpe_set_biospy-options)
- [HPEilodetials.py options](#hpeilodetialspy-options)
- [Secure Boot and certificates](#secure-boot-and-certificates)
- [Exit codes](#exit-codes)
- [Repository structure](#repository-structure)
- [Troubleshooting](#troubleshooting)

## Scripts

| Script | Description |
|--------|-------------|
| **HPE_set_bios.py** | Set BIOS attributes via iLO Redfish (idempotent). Optional BIOS: built-in Nutanix profiles, file-based profiles, or Secure Boot/cert/reboot only. |
| **HPEilodetials.py** | Collect hardware inventory from iLOs (CSV/JSON). Optional: export BIOS settings per model/CPU for use with HPE_set_bios.py. |

## Requirements

- Python 3.6+ (3.8+ recommended)
- HPE `python-ilorest-library` (provides Redfish client for iLO)
- Network access to iLO management IPs (HTTPS, default port 443)

```bash
pip install -r requirements.txt
```

## Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| **ILO_USER** | iLO username | `Administrator` |
| **ILO_PASSWORD** | iLO password (required for apply/check/fetch) | (none) |
| **ILO_TIMEOUT** | API timeout in seconds | 60 (set_bios), 30 (inventory) |
| **ILO_INPUT_FILE** | Default file for iLO IPs with `-f` | `ips.txt` |

Use `-u` / `-p` on the command line to override. Prefer env vars in production to avoid passwords in process lists.

## BIOS profiles

Built-in Nutanix profiles (Virtualization-MaxPerformance):

- **Nutanix_DL360G11_Intel** – HPE ProLiant DL360 Gen11 (Intel Xeon)
- **Nutanix_DL385G11_AMD** – HPE ProLiant DL385 Gen11 (AMD EPYC)

The same profiles are available as text files in `bios_profiles/` for `--bios-settings-file` and `--match-model-cpu`:

- `bios_profiles/Nutanix_DL360G11_Intel.txt`
- `bios_profiles/Nutanix_DL385G11_AMD.txt`

File format: `# Model=...`, `# CPU=...`, `# CPU_Model=...` header, then `key=value` per line.

## Quick start

**Inventory (list of iLO IPs in `ips.txt`):**
```bash
python HPEilodetials.py -f ips.txt -p 'your_password' -o inventory.csv
```

**Apply Nutanix profile (auto-detect Intel/AMD):**
```bash
python HPE_set_bios.py -f ips.txt -p 'your_password'
```

**Apply profile from file, only when model/CPU match:**
```bash
python HPE_set_bios.py -f ips.txt -p 'your_password' \
  --bios-settings-file bios_profiles/Nutanix_DL360G11_Intel.txt \
  --match-model-cpu
```

**Use named profile explicitly:**
```bash
python HPE_set_bios.py -f ips.txt -p 'your_password' --bios-profile Nutanix_DL385G11_AMD
```

**Export BIOS from reference servers (one file per model+CPU):**
```bash
python HPEilodetials.py -f ips.txt -p 'your_password' --fetch-bios-settings ./bios_profiles
```

**Secure Boot + certificate (no BIOS changes):**
```bash
python HPE_set_bios.py -f ips.txt -p 'your_password' --no-bios \
  --enable-secure-boot --secure-boot-cert Nutanix_Secure_Boot_v3.cer --reboot
```

## HPE_set_bios.py options

| Option | Description |
|--------|-------------|
| `ilo_ip` or `-f FILE` | One or more iLO IPs, or file with one IP per line |
| `-u`, `-p` | Username and password |
| `--check` | Compare current BIOS to desired (read-only); exit 0 if match |
| `--dry-run` | Print desired attributes only; no connect or PATCH |
| `--bios-settings-file FILE` | Apply BIOS from key=value file (optional Model/CPU header) |
| `--bios-profile NAME` | Use named profile: `Nutanix_DL360G11_Intel`, `Nutanix_DL385G11_AMD` |
| `--fetch-bios-settings FILE` | Export current BIOS + model/CPU from first target to FILE; then exit |
| `--no-bios` | Do not apply any BIOS (only Secure Boot / cert / reboot if requested) |
| `--match-model-cpu` | With file: apply only if server model and CPU match file header |
| `--enable-secure-boot` | Enable Secure Boot (Redfish + BIOS attributes) |
| `--disable-secure-boot` | Disable Secure Boot |
| `--secure-boot-cert FILE` | Import certificate into Secure Boot db (e.g. Nutanix .cer); BIOS in User mode required |
| `--reboot` | Reboot server(s) after applying (no prompt) |
| `--no-reboot-prompt` | Do not ask to reboot |
| `--no-verify-ssl` | Disable SSL verification (lab only) |
| `--version` | Print script version and exit |

## HPEilodetials.py options

| Option | Description |
|--------|-------------|
| `-i`, `--input FILE` | File with one iLO IP per line (default: `ips.txt`) |
| `-o`, `--output-csv FILE` | Write CSV or JSON to FILE |
| `-u`, `-p` | Username and password |
| `--fetch-bios-settings DIR` | Export current BIOS + model/CPU to DIR (one file per model+CPU) |
| `--format csv|json` | Stdout format (default: csv) |
| `--strict` | Exit with failure if any node fails |
| `--workers N` | Parallel workers (default: 2) |
| `--no-verify-ssl` | Disable SSL verification (lab only) |
| `--version` | Print script version and exit |

## Secure Boot and certificates

- **Enable:** `--enable-secure-boot` sets Secure Boot on and uses factory/default keys (suitable for AHV).
- **Certificate:** Use `--secure-boot-cert <file>` to import a PEM or DER certificate (e.g. Nutanix Secure Boot) into the Authorized Signature Database (db). **BIOS must be in User mode** for enrollment.
- **Disable:** `--disable-secure-boot` turns Secure Boot off via Redfish and BIOS attributes.
- Reboot is required for Secure Boot and BIOS changes to take effect.

## Exit codes

| Script | 0 | 1 | 2 |
|--------|---|---|---|
| **HPE_set_bios.py** | Success | One or more nodes failed / check mismatch | Usage error (missing args, file not found) |
| **HPEilodetials.py** | All nodes OK | One or more nodes failed | Usage error (e.g. input file not found) |

## Repository structure

```
.
├── HPE_set_bios.py          # BIOS configuration and Secure Boot
├── HPEilodetials.py         # Inventory collection
├── requirements.txt         # Python dependencies
├── README.md                # This file
├── ips.txt.example          # Example IP list (copy to ips.txt)
├── .gitignore
└── bios_profiles/
    ├── Nutanix_DL360G11_Intel.txt
    └── Nutanix_DL385G11_AMD.txt
```

Do not commit `ips.txt` (real IPs) or passwords; use environment variables or secure secret management.

## Troubleshooting

- **RedfishClient / import errors:** Uninstall the generic `redfish` package and use only `python-ilorest-library`: `pip uninstall redfish -y && pip install -r requirements.txt`
- **Certificate import fails:** Ensure BIOS/Platform is in **User mode** (not Setup). Use `--debug-secure-boot` with one IP to inspect Secure Boot and BIOS state.
- **BIOS PATCH 400/404:** Attribute names can vary by platform/ROM; use `--fetch-bios-settings` on a working node and apply that file, or try the other built-in profile.
- **Node skipped / timeout:** Check network and iLO reachability; increase `--timeout` or `--probe-timeout` if needed.
