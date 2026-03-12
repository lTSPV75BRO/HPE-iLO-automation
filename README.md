# HPE iLO automation scripts

Production-ready Python scripts for HPE iLO Redfish: inventory collection and BIOS configuration (including Nutanix-oriented profiles and Secure Boot).

## Scripts

| Script | Description |
|--------|-------------|
| **HPE_set_bios.py** | Set BIOS attributes via iLO Redfish (idempotent). Optional BIOS: built-in Nutanix profiles, file-based profiles, or Secure Boot/cert/reboot only. |
| **HPEilodetials.py** | Collect hardware inventory from iLOs (CSV/JSON). Optional: export BIOS settings per model/CPU for use with HPE_set_bios.py. |

## Requirements

- Python 3.6+ (3.8+ recommended)
- HPE `python-ilorest-library` (provides Redfish client for iLO)

```bash
pip install -r requirements.txt
```

## Configuration

- **ILO_USER** – iLO username (default: `Administrator`)
- **ILO_PASSWORD** – iLO password (set in env or use `-p`; required for apply/check)
- **ILO_INPUT_FILE** – Default file for iLO IPs with `-f` (default: `ips.txt`)

## BIOS profiles

Built-in Nutanix profiles (Virtualization-MaxPerformance):

- **Nutanix_DL360G11_Intel** – HPE ProLiant DL360 Gen11 (Intel)
- **Nutanix_DL385G11_AMD** – HPE ProLiant DL385 Gen11 (AMD)

The same profiles are available as files in `bios_profiles/` for use with `--bios-settings-file` and `--match-model-cpu`:

- `bios_profiles/Nutanix_DL360G11_Intel.txt`
- `bios_profiles/Nutanix_DL385G11_AMD.txt`

## Quick start

**Inventory (list of iLO IPs in `ips.txt`):**
```bash
python HPEilodetials.py -f ips.txt -p 'your_password' -o inventory.csv
```

**Apply Nutanix Intel profile to all targets (auto-detect CPU):**
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

## Git

This directory is set up as a Git repository. Do not commit passwords or `ips.txt` if it contains sensitive IPs; use `.gitignore` and env vars for secrets.

```bash
git init
git add HPE_set_bios.py HPEilodetials.py requirements.txt README.md .gitignore bios_profiles/
git commit -m "Add HPE iLO BIOS and inventory scripts with Nutanix profiles"
```
