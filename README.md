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
- [License](#license)
- [Contributing](#contributing)

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

Nutanix-recommended profiles are built in; use `--bios-profile NAME` or `--bios-settings-file bios_profiles/NAME.txt`.

**HPE DX/DL Gen10**

| Profile | Platform |
|---------|----------|
| `Nutanix_Gen10_Intel` | All HPE Gen10 systems (Intel): Custom workload, OsControl, SR-IOV/VT-d/APIC |

**HPE Gen10 Plus**

| Profile | Platform |
|---------|----------|
| `Nutanix_Gen10Plus_DX360_10SFF_Intel` | DX360-10SFF ALL NVMe (Intel) |
| `Nutanix_Gen10Plus_DX360_10SFF_VMD_Intel` | DX360-10SFF VMD NVMe (Intel) |
| `Nutanix_Gen10Plus_DX360_8SFF_Intel` | DX360-8SFF (8+2 NVMe) |
| `Nutanix_Gen10Plus_DX360_8SFF_VMD_Intel` | DX360-8SFF VMD NVMe |
| `Nutanix_Gen10Plus_DX385_24SFF_AMD` | DX385-24SFF (AMD) |
| `Nutanix_Gen10Plus_DX325_8SFF_Intel` | DX325-8SFF |
| `Nutanix_Gen10Plus_DX220n_Intel` | ProLiant DX220n |
| `Nutanix_Gen10Plus_DX380_24SFF_Intel` | DX380-24SFF |
| `Nutanix_Gen10Plus_DX380_12LFF_Intel` | DX380-12LFF |
| `Nutanix_Gen10Plus_DX380_8SFF_Intel` | DX380-8SFF |
| `Nutanix_Gen10Plus_DX385_12_AMD` | DX385-12 (AMD) |
| `Nutanix_Gen10Plus_EL8000_Intel` | ProLiant e920 (Edgeline EL8000) |

**HPE Gen11 (DL/DX)**

| Profile | Platform |
|---------|----------|
| `Nutanix_DL360G11_Intel` | All Gen11 Intel (e.g. DL360 Gen11) |
| `Nutanix_DL385G11_AMD` | All Gen11 AMD (e.g. DL385 Gen11) |
| `Nutanix_Gen11_DX360_10SFF_VMD_Intel` | DX360-10SFF NVMe VMD |
| `Nutanix_Gen11_DX360_8SFF_VMD_Intel` | DX360-8SFF+2 NVMe VMD |
| `Nutanix_Gen11_DX365_10SFF_VMD_AMD` | DX365-10SFF ALL NVMe VMD (AMD) |

**HPE Gen12 (DL/DX) – Nutanix required settings**

| Profile | Platform |
|---------|----------|
| `Nutanix_Gen12_Intel` | DL360 Gen12, DL380 Gen12 (Intel). **Critical:** PCIe Multi-Segment=Disabled (required for Foundation 5.10+ and AOS 7.5+), Workload Profile=Virtualization-MaxPerformance, Boot Mode=UEFI. Use `--enable-secure-boot` and `--secure-boot-cert` when Secure Boot is required. |

All of the above are also available as `bios_profiles/<NAME>.txt` for `--bios-settings-file` and `--match-model-cpu`. File format: `# Model=...`, `# CPU=...`, `# CPU_Model=...` header, then `key=value` per line.

**Auto-selection by model:** When you do not pass `--bios-profile` or `--bios-settings-file`, the script picks a profile from the detected iLO **model**. Gen10 nodes get a Gen10 profile; Gen11 nodes get a Gen11 profile; Gen12 Intel (DL360/DL380/DX360/DX380) get `Nutanix_Gen12_Intel` with the required PCIe Multi-Segment, Boot Mode, and Workload Profile settings. So a generic Gen10 node will not receive Gen11/Gen12 settings.

**HPE supported hardware:** For the official list of Nutanix-supported HPE platforms and compatibility, see [Nutanix Hardware Platforms – HPE](https://www.nutanix.com/products/hardware-platforms/specsheet?platformProvider=HPE) and [HPE DL Compute Server HW/FW Compatibility](https://portal.nutanix.com/page/documents/details?targetId=HPE-DL-Compute-Server-HW-FW-Compatibility:HPE-DL-Compute-Server-HW-FW-Compatibility).

**Product name / model mapping (Foundation):** Product Name in iLO and Model in `hardware_config.json` are set by Nutanix Foundation during imaging. If a node is reset to default settings, that mapping can be lost. Profile files use `# Model=` set to the iLO Product Name where applicable so `--match-model-cpu` applies the correct profile. Reference mapping (iLO Product Name → hardware_config.json Model):

| Product Name in iLO | Model in hardware_config.json |
|--------------------|-------------------------------|
| ProLiant DX360 Gen10 4LFF | HPE DX360-4 G10 |
| ProLiant DX360 Gen10 8SFF | HPE DX360-8 G10 |
| ProLiant DX360 Gen10 10NVMe | HPE DX360-10 G10 |
| ProLiant DX380 Gen10 8SFF | HPE DX380-8 G10 |
| ProLiant DX380 Gen10 12LFF | HPE DX380-12 G10 |
| ProLiant DX380 Gen10 24SFF | HPE DX380-24 G10 |
| ProLiant DX360 Gen10 Plus 4LFF | HPE DX360-4 G10 Plus |
| ProLiant DX360 Gen10 Plus 8SFF | HPE DX360-8 G10 Plus |
| ProLiant DX380 Gen10 Plus 8SFF | HPE DX380-8 G10 Plus |
| ProLiant DX360 Gen10 Plus 10NVMe | HPE DX360-10 G10 Plus |
| ProLiant DX380 Gen10 Plus 12LFF | HPE DX380-12 G10 Plus |
| ProLiant DX380 Gen10 Plus 24SFF | HPE DX380-24 G10 Plus |
| (+ FSC variants: 4LFF/8SFF/12LFF/24SFF) | HPE DX... G10 Plus FSC |

Gen11 systems (e.g. ProLiant DX360 Gen11 10NVMe) are shown by the script using the iLO product name as reported.

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

**Reset BIOS to factory default (then reboot if desired):**
```bash
python HPE_set_bios.py -f ips.txt -p 'your_password' --reset-bios-to-default [--reboot]
```

**Note:** For nodes in a Nutanix cluster with workloads, use **`rolling_restart -h`** on the CVM to restart nodes safely instead of rebooting via iLO from this script.

## HPE_set_bios.py options

| Option | Description |
|--------|-------------|
| `ilo_ip` or `-f FILE` | One or more iLO IPs, or file with one IP per line |
| `-u`, `-p` | Username and password |
| `--password-file FILE` | Per-iLO passwords: one line per host as `IP password` or `IP,password`; `-p` used for IPs not in file |
| `--check` | Compare current BIOS to desired (read-only); exit 0 if match |
| `--dry-run` | Print desired attributes only; no connect or PATCH |
| `--bios-settings-file FILE` | Apply BIOS from key=value file (optional Model/CPU header) |
| `--bios-profile NAME` | Use named profile: `Nutanix_DL360G11_Intel`, `Nutanix_DL385G11_AMD` |
| `--fetch-bios-settings FILE` | Export current BIOS + model/CPU from first target to FILE; then exit |
| `--no-write` | With `--fetch-bios-settings`: do not write to file; print BIOS export to screen (e.g. when no write permission) |
| `--no-bios` | Do not apply any BIOS (only Secure Boot / cert / reboot if requested) |
| `--match-model-cpu` | With file: apply only if server model and CPU match file header |
| `--enable-secure-boot` | Enable Secure Boot (Redfish + BIOS attributes) |
| `--disable-secure-boot` | Disable Secure Boot |
| `--secure-boot-cert FILE` | Import certificate into Secure Boot db (e.g. Nutanix .cer); BIOS in User mode required |
| `--reboot` | Reboot server(s) after applying (no prompt) |
| `--no-reboot-prompt` | Do not ask to reboot |
| `--reset-bios-to-default` | Reset BIOS to factory default (no profile apply). Use with `--reboot` to reboot after reset. |
| `--no-verify-ssl` | Disable SSL verification (lab only) |
| `--version` | Print script version and exit |

**Rebooting nodes in a cluster:** For HPE nodes that are in a Nutanix cluster with running workloads, do **not** reboot them directly via this script’s prompt or `--reboot` for the whole list. Use **`rolling_restart -h`** on a CVM to restart nodes safely (one at a time, with workload migration). Example on CVM: `rolling_restart -h` for usage.

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
├── LICENSE                  # MIT License
├── CONTRIBUTING.md          # Contribution guidelines
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

## License

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for the full text.

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) for how to report issues, suggest changes, and submit pull requests.
