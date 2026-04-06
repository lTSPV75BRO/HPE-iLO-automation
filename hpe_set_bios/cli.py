#!/usr/bin/env python3
"""
Set HPE node BIOS attributes via iLO Redfish API (production-ready).

BIOS settings are optional: use built-in Intel/AMD profile, a text file (--bios-settings-file),
or --no-bios to only run Secure Boot / cert / reboot. Idempotent: only PATCHes attributes that differ.

Configuration:
  Environment variables (override CLI defaults):
    ILO_USER         - iLO username (default: Administrator)
    ILO_PASSWORD     - iLO password (required; no default)
    ILO_TIMEOUT      - Request timeout in seconds (default: 60)
    ILO_INPUT_FILE   - File with one iLO IP per line when using -f (default: ips.txt)
  Use -u/--user and -p/--password for CLI; password from ILO_PASSWORD if -p not set.
  Different credentials per iLO: use -f FILE with optional username/password per line (IP, or "IP password", or "IP username password"; comma or space). Missing username/password use -u and -p.

  Multiple iLOs: pass several IPs (ilo_ip ilo_ip ...) or use -f/--file with one IP per line.
  With multiple targets, reboot is never prompted; use --reboot to reboot all after applying.
  For HPE nodes in a Nutanix cluster with running workloads, use rolling_restart -h on the CVM to restart nodes safely instead of rebooting via iLO from this script.
  If the Rest API fails for an iLO, the script retries up to 3 times, then skips that node and continues.
  Before each node, a short probe (default 10s timeout) confirms iLO REST is alive; unresponsive nodes are skipped.

  BIOS from file: --fetch-bios-settings FILE exports current BIOS + model/CPU from a reference server.
  --bios-settings-file FILE applies that file to targets; --match-model-cpu applies only when model/CPU match.

Secure Boot: Use --enable-secure-boot to set Secure Boot Enforcement=Enabled and
  Mode=Standard (factory default keys; suitable for AHV). Use --secure-boot-cert <file>
  to import a certificate (e.g. Nutanix_Secure_Boot_v3.cer) into the Authorized
  Signature Database (db); PEM and DER .cer files are supported.
  Certificate enrollment requires BIOS/Platform to be in User mode (not Setup mode).

Requires: python-ilorest-library
  pip install -r requirements.txt
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import logging
import os
import sys
import time
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

# Module-level logger; configured in main() when --log-file or --verbose is used.
logger = logging.getLogger("hpe_set_bios")

if sys.version_info < (3, 6):
    print("Error: This script requires Python 3.6 or later.", file=sys.stderr)
    sys.exit(2)

# Suppress urllib3 NotOpenSSLWarning on systems where Python's ssl is linked to LibreSSL
warnings.filterwarnings("ignore", message=".*urllib3 v2 only supports OpenSSL.*")

__version__ = "1.0.0"

try:
    from redfish import RedfishClient
except ImportError:
    try:
        from redfish.rest.v1 import RedfishClient
    except ImportError:
        print(
            "Error: RedfishClient not found. Install: pip install python-ilorest-library",
            file=sys.stderr,
        )
        sys.exit(1)

# --- Config ---
DEFAULT_USERNAME = os.environ.get("ILO_USER", "Administrator")
DEFAULT_PASSWORD = os.environ.get("ILO_PASSWORD", "")
DEFAULT_TIMEOUT = int(os.environ.get("ILO_TIMEOUT", "60"))
DEFAULT_INPUT_FILE = os.environ.get("ILO_INPUT_FILE", "ips.txt")
FILE_ENCODING = "utf-8"
BIOS_URI = "/redfish/v1/Systems/1/Bios/"
BIOS_SETTINGS_URI = "/redfish/v1/Systems/1/Bios/Settings/"
# Trailing slash required by some iLO versions (HPE Redfish examples)
SYSTEM_RESET_URI = "/redfish/v1/Systems/1/Actions/ComputerSystem.Reset/"
BIOS_RESET_TO_DEFAULT_URI = "/redfish/v1/Systems/1/Bios/Actions/Bios.ResetBios/"
SYSTEM_URI = "/redfish/v1/Systems/1/"

# Max Rest API retries per iLO before skipping to next node
MAX_ILO_RETRIES = 3
# Short timeout (seconds) to probe if iLO REST is alive before full check/set
PROBE_TIMEOUT = 10
REDFISH_ROOT_URI = "/redfish/v1/"

# Profiles: prefer repo root bios_profiles/, then package dir, then cwd.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_PARENT_DIR = os.path.dirname(SCRIPT_DIR)
_CANDIDATES = [
    os.path.join(_PARENT_DIR, "bios_profiles"),
    os.path.join(SCRIPT_DIR, "bios_profiles"),
    os.path.join(os.getcwd(), "bios_profiles"),
]
BIOS_PROFILES_DIR = next((p for p in _CANDIDATES if os.path.isdir(p)), _CANDIDATES[1])
DEFAULT_INTEL_PROFILE = "Nutanix_DL360G11_Intel"
DEFAULT_AMD_PROFILE = "Nutanix_DL385G11_AMD"

# iLO Product Name → Model in hardware_config.json (Foundation). Used for display.
# First match (longest substring) wins; order more specific first.
# Gen11: display iLO name as-is (e.g. ProLiant DX360 Gen11 10NVMe); only Gen10/Gen10 Plus mapped below.
ILO_MODEL_TO_DISPLAY: List[Tuple[str, str]] = [
    # Gen10 Plus
    ("ProLiant DX360 Gen10 Plus 10NVMe", "HPE DX360-10 G10 Plus"),
    ("ProLiant DX360 Gen10 Plus 8SFF", "HPE DX360-8 G10 Plus"),
    ("ProLiant DX360 Gen10 Plus 4LFF", "HPE DX360-4 G10 Plus"),
    ("ProLiant DX380 Gen10 Plus 24SFF", "HPE DX380-24 G10 Plus"),
    ("ProLiant DX380 Gen10 Plus 12LFF", "HPE DX380-12 G10 Plus"),
    ("ProLiant DX380 Gen10 Plus 8SFF", "HPE DX380-8 G10 Plus"),
    # Gen10
    ("ProLiant DX360 Gen10 10NVMe", "HPE DX360-10 G10"),
    ("ProLiant DX360 Gen10 8SFF", "HPE DX360-8 G10"),
    ("ProLiant DX360 Gen10 4LFF", "HPE DX360-4 G10"),
    ("ProLiant DX380 Gen10 24SFF", "HPE DX380-24 G10"),
    ("ProLiant DX380 Gen10 12LFF", "HPE DX380-12 G10"),
    ("ProLiant DX380 Gen10 8SFF", "HPE DX380-8 G10"),
]


def _model_display_name(ilo_model: str) -> str:
    """Return hardware_config.json-style model name for display, or ilo_model if no mapping."""
    if not ilo_model or ilo_model == "Unknown":
        return ilo_model or "Unknown"
    for key, display in ILO_MODEL_TO_DISPLAY:
        if key in ilo_model:
            return display
    return ilo_model


# iLO Model (substring match) → profile name for auto-selection when no --bios-profile/--bios-settings-file.
# First match wins; order more specific first. Ensures Gen10 gets Gen10 profile, Gen11/Gen12 get Gen11 profile.
# Gen12 Intel: Nutanix_Gen12_Intel (PcieMultiSegment=Disabled, WorkloadProfile, BootMode=Uefi required for Foundation/AOS/LCM).
# Refs: https://www.nutanix.com/products/hardware-platforms/specsheet?platformProvider=HPE
#       https://portal.nutanix.com/page/documents/details?targetId=HPE-DL-Compute-Server-HW-FW-Compatibility:HPE-DL-Compute-Server-HW-FW-Compatibility
MODEL_TO_PROFILE: List[Tuple[str, str]] = [
    # Gen12 (G12) Intel – Nutanix_Gen12_Intel (critical: PcieMultiSegment=Disabled, BootMode=Uefi, WorkloadProfile)
    ("ProLiant DL380 Gen12 24NVMe", "Nutanix_Gen12_Intel"),
    ("ProLiant DL380 Gen12", "Nutanix_Gen12_Intel"),
    ("ProLiant DL360 Gen12", "Nutanix_Gen12_Intel"),
    ("ProLiant DX380 Gen12", "Nutanix_Gen12_Intel"),
    ("ProLiant DX360 Gen12", "Nutanix_Gen12_Intel"),
    # Gen12 AMD – use Gen11 AMD profile until Gen12 AMD–specific profile is added
    ("ProLiant DL385 Gen12", "Nutanix_DL385G11_AMD"),
    ("ProLiant DX385 Gen12", "Nutanix_DL385G11_AMD"),
    # Gen11 – specific first
    ("ProLiant DX360 Gen11 10NVMe", "Nutanix_Gen11_DX360_10SFF_VMD_Intel"),
    ("ProLiant DX360 Gen11 8SFF", "Nutanix_Gen11_DX360_8SFF_VMD_Intel"),
    ("ProLiant DX365 Gen11", "Nutanix_Gen11_DX365_10SFF_VMD_AMD"),
    ("ProLiant DX360 Gen11", "Nutanix_DL360G11_Intel"),
    ("ProLiant DX380 Gen11", "Nutanix_DL360G11_Intel"),
    ("ProLiant DL360 Gen11", "Nutanix_DL360G11_Intel"),
    ("ProLiant DL385 Gen11", "Nutanix_DL385G11_AMD"),
    ("ProLiant DX385 Gen11", "Nutanix_DL385G11_AMD"),
    # Gen10 Plus – Intel
    ("ProLiant DX360 Gen10 Plus 10NVMe", "Nutanix_Gen10Plus_DX360_10SFF_Intel"),
    ("ProLiant DX360 Gen10 Plus 8SFF", "Nutanix_Gen10Plus_DX360_8SFF_Intel"),
    ("ProLiant DX360 Gen10 Plus 4LFF", "Nutanix_Gen10Plus_DX360_8SFF_Intel"),
    ("ProLiant DX380 Gen10 Plus 24SFF", "Nutanix_Gen10Plus_DX380_24SFF_Intel"),
    ("ProLiant DX380 Gen10 Plus 12LFF", "Nutanix_Gen10Plus_DX380_12LFF_Intel"),
    ("ProLiant DX380 Gen10 Plus 8SFF", "Nutanix_Gen10Plus_DX380_8SFF_Intel"),
    ("ProLiant DX220n Gen10 Plus", "Nutanix_Gen10Plus_DX220n_Intel"),
    ("ProLiant DX325 Gen10 Plus", "Nutanix_Gen10Plus_DX325_8SFF_Intel"),
    ("ProLiant e920", "Nutanix_Gen10Plus_EL8000_Intel"),
    ("ProLiant DX360 Gen10 Plus", "Nutanix_Gen10Plus_DX360_10SFF_Intel"),
    ("ProLiant DX380 Gen10 Plus", "Nutanix_Gen10Plus_DX380_24SFF_Intel"),
    # Gen10 Plus – AMD
    ("ProLiant DX385 Gen10 Plus 24SFF", "Nutanix_Gen10Plus_DX385_24SFF_AMD"),
    ("ProLiant DX385 Gen10 Plus 12", "Nutanix_Gen10Plus_DX385_12_AMD"),
    ("ProLiant DX385 Gen10 Plus", "Nutanix_Gen10Plus_DX385_24SFF_AMD"),
    # Gen10 (non-Plus) – all use Nutanix_Gen10_Intel
    ("ProLiant DX360 Gen10", "Nutanix_Gen10_Intel"),
    ("ProLiant DX380 Gen10", "Nutanix_Gen10_Intel"),
    ("ProLiant DL360 Gen10", "Nutanix_Gen10_Intel"),
    ("ProLiant DL380 Gen10", "Nutanix_Gen10_Intel"),
]


def _profile_for_model(ilo_model: str, is_amd: bool) -> Optional[str]:
    """Return profile name for this model (and CPU), or None to use default Gen11 Intel/AMD profile."""
    if not ilo_model or ilo_model == "Unknown":
        return None
    for key, profile_name in MODEL_TO_PROFILE:
        if key in ilo_model:
            return profile_name
    return None


def _get_profile_path(profile_name: str) -> str:
    """Path to profile file (bios_profiles/<name>.txt)."""
    return os.path.join(BIOS_PROFILES_DIR, profile_name + ".txt")


def _list_profile_names() -> List[str]:
    """Return list of profile names from bios_profiles/*.txt (stem only)."""
    if not os.path.isdir(BIOS_PROFILES_DIR):
        return []
    names = []
    for f in os.listdir(BIOS_PROFILES_DIR):
        if f.endswith(".txt") and not f.startswith("."):
            names.append(f[:-4])
    return sorted(names)


def _validate_bios_settings_file(path: str) -> Tuple[bool, List[str]]:
    """Validate a BIOS settings file (key=value lines, optional # Model= etc). Returns (ok, list of error messages)."""
    errors: List[str] = []
    try:
        attrs, meta = _load_bios_settings_file(path)
        if not attrs and not meta:
            errors.append("File is empty or has no key=value lines.")
        for k, v in (attrs or {}).items():
            if not k or not k.strip():
                errors.append("Empty attribute name")
            if "=" in k and not k.strip().startswith("#"):
                # key=value: key should not contain = except for the separator
                pass
        return (len(errors) == 0, errors)
    except FileNotFoundError:
        return False, [f"File not found: {path}"]
    except OSError as e:
        return False, [f"Read error: {e}"]


def _load_profile_by_name(profile_name: str) -> Tuple[Optional[Dict[str, str]], Optional[Dict[str, str]]]:
    """Load profile from bios_profiles/<name>.txt. Returns (attrs, metadata) or (None, None) on error."""
    path = _get_profile_path(profile_name)
    try:
        return _load_bios_settings_file(path)
    except (OSError, FileNotFoundError):
        return None, None


# Secure Boot: Enforcement Enabled, Mode Standard (factory default keys; for AHV/Nutanix).
# Attribute names may vary by platform (e.g. SecureBootPolicy vs SecureBootMode); check registry if PATCH fails.
SECURE_BOOT_ATTRIBUTES = {
    "SecureBoot": "Enabled",
    "SecureBootMode": "UserMode",
}
# BIOS attributes to disable Secure Boot (used with --disable-secure-boot)
SECURE_BOOT_DISABLED_ATTRIBUTES = {
    "SecureBoot": "Disabled",
}
# Redfish SecureBoot resource – PATCH here to enable/disable (trailing slash required on some iLOs)
SECURE_BOOT_URI = "/redfish/v1/Systems/1/SecureBoot/"
# Authorized Signature Database (db). POST to Certificates/ (or Payload) to enroll (BIOS in User mode required).
# HPE doc: CertificateString (PEM) + CertificateType "PEM". Try multiple URIs and payload formats.
SECURE_BOOT_DB_CERTIFICATES_URI = "/redfish/v1/Systems/1/SecureBoot/SecureBootDatabases/db/Certificates/"
SECURE_BOOT_DB_CERTIFICATES_PAYLOAD_URI = "/redfish/v1/Systems/1/SecureBoot/SecureBootDatabases/db/Certificates/Payload"
SECURE_BOOT_DB_CERTIFICATES_COLLECTION_URI = "/redfish/v1/Systems/1/SecureBoot/SecureBootDatabases/db/Certificates"

# Additional URIs seen on some iLO/Redfish implementations (not used in this simplified flow).
SECURE_BOOT_CERT_POST_URIS_EXTRA: List[str] = []

def _get_attributes(client: Any, uri: str) -> Dict[str, Any]:
    """GET resource and return its Attributes dict, or empty dict on error."""
    try:
        resp = client.get(uri)
        if resp.status not in (200, 201):
            return {}
        data = getattr(resp, "dict", None) or getattr(resp, "data", None)
        if not data:
            return {}
        return dict(data.get("Attributes") or {})
    except Exception:
        return {}


def _is_amd_processor(client: Any) -> bool:
    """Return True if the system has an AMD processor (from Redfish Processors or System)."""
    try:
        sys_resp = client.get(SYSTEM_URI)
        if sys_resp.status != 200:
            return False
        sys_data = getattr(sys_resp, "dict", None) or getattr(sys_resp, "data", None)
        if not sys_data:
            return False
        proc_ref = sys_data.get("Processors")
        if isinstance(proc_ref, dict):
            proc_ref = proc_ref.get("@odata.id")
        elif not isinstance(proc_ref, str):
            proc_ref = None
        if not proc_ref:
            return False
        proc_resp = client.get(proc_ref)
        if proc_resp.status != 200:
            return False
        proc_data = getattr(proc_resp, "dict", None) or getattr(proc_resp, "data", None)
        members = (proc_data or {}).get("Members", [])
        if not isinstance(members, list):
            members = []
        for m in members[:2]:  # check first 2 in case of 2P
            try:
                member_ref = m.get("@odata.id") if isinstance(m, dict) else (m if isinstance(m, str) else None)
                if not member_ref:
                    continue
                one = client.get(member_ref)
                if one.status != 200:
                    continue
                one_data = getattr(one, "dict", None) or getattr(one, "data", None)
                model = (one_data or {}).get("Model") or (one_data or {}).get("ProcessorId", {}).get("VendorId") or ""
                if "AMD" in str(model).upper():
                    return True
            except Exception:
                continue
        return False
    except Exception:
        return False


def _get_desired_attributes(is_amd: bool) -> Dict[str, str]:
    """Load default profile from bios_profiles/ (Intel or AMD) and return attributes dict."""
    name = DEFAULT_AMD_PROFILE if is_amd else DEFAULT_INTEL_PROFILE
    attrs, _ = _load_profile_by_name(name)
    if not attrs:
        print(f"Warning: Default profile '{name}' not found in {BIOS_PROFILES_DIR}; no BIOS attributes to apply.", file=sys.stderr)
    return dict(attrs) if attrs else {}


def _get_system_model_cpu(client: Any) -> Tuple[str, str, str]:
    """Return (model, cpu_vendor, cpu_model) from Redfish. cpu_vendor is 'Intel' or 'AMD'."""
    model = "Unknown"
    cpu_vendor = "Intel"
    cpu_model = "Unknown"
    try:
        sys_resp = client.get(SYSTEM_URI)
        if sys_resp.status != 200:
            return model, cpu_vendor, cpu_model
        sys_data = getattr(sys_resp, "dict", None) or getattr(sys_resp, "data", None)
        if not sys_data:
            return model, cpu_vendor, cpu_model
        model = (sys_data.get("Model") or "Unknown").strip()
        proc_ref = sys_data.get("Processors")
        if isinstance(proc_ref, dict):
            proc_ref = proc_ref.get("@odata.id")
        elif not isinstance(proc_ref, str):
            proc_ref = None
        if not proc_ref:
            return model, cpu_vendor, cpu_model
        proc_resp = client.get(proc_ref)
        if proc_resp.status != 200:
            return model, cpu_vendor, cpu_model
        proc_data = getattr(proc_resp, "dict", None) or getattr(proc_resp, "data", None)
        members = (proc_data or {}).get("Members", [])
        if not isinstance(members, list):
            members = []
        for m in members[:2]:
            try:
                member_ref = m.get("@odata.id") if isinstance(m, dict) else (m if isinstance(m, str) else None)
                if not member_ref:
                    continue
                one = client.get(member_ref)
                if one.status != 200:
                    continue
                one_data = getattr(one, "dict", None) or getattr(one, "data", None)
                cpu_model = (one_data or {}).get("Model") or (one_data or {}).get("ProcessorId", {}).get("VendorId") or "Unknown"
                cpu_model = str(cpu_model).strip()
                if "AMD" in cpu_model.upper():
                    cpu_vendor = "AMD"
                else:
                    cpu_vendor = "Intel"
                break
            except Exception:
                continue
    except Exception:
        pass
    return model, cpu_vendor, cpu_model


def _load_bios_settings_file(path: str) -> Tuple[Dict[str, str], Dict[str, str]]:
    """
    Load BIOS settings from a text file. Returns (attributes_dict, metadata_dict).
    Format: lines with key=value; lines starting with # Model=, # CPU=, # CPU_Model= set metadata.
    Empty lines and #-only lines are ignored. Supports UTF-8.
    """
    metadata: Dict[str, str] = {}
    attributes: Dict[str, str] = {}
    with open(path, "r", encoding=FILE_ENCODING, errors="replace") as f:
        for line in f:
            line = line.rstrip("\n\r")
            s = line.strip()
            if not s:
                continue
            if s.startswith("#"):
                rest = s[1:].strip()
                if "=" in rest:
                    k, _, v = rest.partition("=")
                    k, v = k.strip(), v.strip()
                    if k in ("Model", "CPU", "CPU_Model"):
                        metadata[k] = v
                continue
            if "=" in s:
                k, _, v = s.partition("=")
                attributes[k.strip()] = v.strip()
    return attributes, metadata


def _bios_export_lines(model: str, cpu_vendor: str, cpu_model: str, attributes: Dict[str, str]) -> List[str]:
    """Build BIOS export lines (header + key=value). Used for file write or screen output."""
    lines = [
        "# BIOS settings export from iLO Redfish",
        f"# Model={model}",
        f"# CPU={cpu_vendor}",
        f"# CPU_Model={cpu_model}",
        "",
    ]
    for k in sorted(attributes.keys()):
        v = attributes.get(k, "")
        v_flat = str(v).replace("\n", " ").replace("\r", "")
        lines.append(f"{k}={v_flat}")
    return lines


def _save_bios_settings_file(path: str, model: str, cpu_vendor: str, cpu_model: str, attributes: Dict[str, str]) -> None:
    """Write BIOS settings to a text file with metadata header (Model, CPU, CPU_Model)."""
    lines = _bios_export_lines(model, cpu_vendor, cpu_model, attributes)
    with open(path, "w", encoding=FILE_ENCODING) as f:
        f.write("\n".join(lines) + "\n")


def fetch_bios_settings(
    ilo_ip: str,
    username: str,
    password: str,
    output_path: str,
    timeout: int = DEFAULT_TIMEOUT,
    verify_ssl: bool = True,
    no_write: bool = False,
    output_format: str = "text",
) -> Tuple[bool, str]:
    """
    GET current BIOS Attributes and system model/CPU from iLO.
    If no_write is False, write to output_path; if True, return the export text as the message (for printing).
    output_format: "text" (default) or "json" (when no_write, message is JSON string).
    Returns (success: bool, message: str).
    """
    client = None
    try:
        kwargs = {"base_url": f"https://{ilo_ip}", "username": username, "password": password, "timeout": timeout}
        if not verify_ssl:
            kwargs["default_verify_cert"] = False
        try:
            client = RedfishClient(**kwargs)
        except TypeError:
            kwargs.pop("default_verify_cert", None)
            client = RedfishClient(**kwargs)
        client.login()
        model, cpu_vendor, cpu_model = _get_system_model_cpu(client)
        attrs = _get_attributes(client, BIOS_URI)
        if not attrs:
            return False, "No BIOS Attributes returned from iLO"
        if no_write:
            if output_format == "json":
                data = {"ilo_ip": ilo_ip, "Model": model, "CPU": cpu_vendor, "CPU_Model": cpu_model, "Attributes": attrs}
                return True, json.dumps(data, indent=2)
            lines = _bios_export_lines(model, cpu_vendor, cpu_model, attrs)
            return True, "\n".join(lines) + "\n"
        _save_bios_settings_file(output_path, model, cpu_vendor, cpu_model, attrs)
        return True, f"Saved {len(attrs)} attributes to {output_path} (Model={model}, CPU={cpu_vendor})"
    except Exception as e:
        return False, str(e)
    finally:
        if client is not None:
            try:
                client.logout()
            except Exception:
                pass


def _load_ips(path: str) -> List[str]:
    """Load IPs from file (one per line); skip empty lines and # comments."""
    ips, _, _ = _load_ips_passwords_usernames(path)
    return ips


def _load_ips_passwords_usernames(path: str) -> Tuple[List[str], Dict[str, str], Dict[str, str]]:
    """
    Load IPs and optional per-IP passwords and usernames from one file (-f file).
    One line per target. Format per line:
      IP                    -> use -u and -p for this host
      IP password           -> use -u, this password (password may contain spaces)
      IP username password  -> use this username and password (space-separated; password may contain spaces)
      IP,password           -> use -u, this password (comma-separated)
      IP,username,password  -> use this username and password (comma-separated)
    Skip empty lines and # comments. Returns (list of IPs, dict IP->password, dict IP->username).
    """
    ips: List[str] = []
    passwords: Dict[str, str] = {}
    usernames: Dict[str, str] = {}
    try:
        with open(path, "r", encoding=FILE_ENCODING, errors="replace") as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                if "," in line:
                    parts = [p.strip() for p in line.split(",")]
                    if not parts or not parts[0]:
                        continue
                    ip_part = parts[0]
                    if len(parts) == 1:
                        pwd_part = ""
                        user_part = ""
                    elif len(parts) == 2:
                        user_part = ""
                        pwd_part = parts[1]
                    else:
                        user_part = parts[1]
                        pwd_part = ",".join(parts[2:]).strip()
                else:
                    parts = line.split(None, 2)
                    if not parts or not parts[0]:
                        continue
                    ip_part = parts[0]
                    if len(parts) == 1:
                        user_part = ""
                        pwd_part = ""
                    elif len(parts) == 2:
                        user_part = ""
                        pwd_part = parts[1]
                    else:
                        user_part = parts[1]
                        pwd_part = parts[2]
                ips.append(ip_part)
                if pwd_part:
                    passwords[ip_part] = pwd_part
                if user_part:
                    usernames[ip_part] = user_part
    except OSError:
        raise
    return ips, passwords, usernames


def probe_ilo_alive(
    ilo_ip: str,
    username: str,
    password: str,
    timeout: int = PROBE_TIMEOUT,
    verify_ssl: bool = True,
) -> bool:
    """Quick check if iLO REST API is reachable (login + GET root). Uses short timeout to avoid hanging."""
    client = None
    try:
        kwargs = {
            "base_url": f"https://{ilo_ip}",
            "username": username,
            "password": password,
            "timeout": timeout,
        }
        if not verify_ssl:
            kwargs["default_verify_cert"] = False
        try:
            client = RedfishClient(**kwargs)
        except TypeError:
            kwargs.pop("default_verify_cert", None)
            client = RedfishClient(**kwargs)
        client.login()
        resp = client.get(REDFISH_ROOT_URI)
        if resp.status not in (200, 201):
            return False
        return True
    except Exception:
        return False
    finally:
        if client is not None:
            try:
                client.logout()
            except Exception:
                pass


def _attributes_to_change(
    desired: Dict[str, str], current: Dict[str, Any]
) -> Dict[str, str]:
    """Return only attributes that differ from current (idempotent)."""
    changes = {}
    for key, want in desired.items():
        cur = current.get(key)
        if cur is None:
            changes[key] = want
        elif str(cur).strip() != str(want).strip():
            changes[key] = want
    return changes


def _load_cert_pem(path: str) -> str:
    """Load certificate from file; return PEM string. Supports PEM or DER (.cer) format."""
    with open(path, "rb") as f:
        data = f.read()
    if b"-----BEGIN CERTIFICATE-----" in data or b"-----BEGIN " in data:
        pem = data.decode("utf-8", errors="replace").strip()
        return pem.replace("\r\n", "\n") + "\n"
    # DER (binary): convert to PEM
    b64 = base64.b64encode(data).decode("ascii")
    lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----\n"


def _enable_secure_boot_resource(client: Any) -> bool:
    """PATCH the Redfish SecureBoot resource to enable (SecureBootEnable=true). Takes effect after reboot."""
    try:
        body = {"SecureBootEnable": True}
        resp = client.patch(SECURE_BOOT_URI, body)
        if resp.status in (200, 204):
            print("Secure Boot enabled via SecureBoot resource (takes effect after reboot).")
            return True
        err = getattr(resp, "text", "") or ""
        print(f"SecureBoot resource PATCH failed: status {resp.status} {err}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"SecureBoot resource PATCH failed: {e}", file=sys.stderr)
        return False


def _disable_secure_boot_resource(client: Any) -> bool:
    """Try to disable Secure Boot: PATCH SecureBoot resource and/or BIOS Attributes. Returns True if any method succeeds."""
    body_sb = {"SecureBootEnable": False}
    # 1. PATCH Redfish SecureBoot resource (try with and without trailing slash)
    for uri in (SECURE_BOOT_URI, "/redfish/v1/Systems/1/SecureBoot"):
        try:
            resp = client.patch(uri, body_sb)
            if resp.status in (200, 201, 202, 204):
                print("Secure Boot disabled via SecureBoot resource (takes effect after reboot).")
                return True
            err = getattr(resp, "text", "") or ""
            print(f"  SecureBoot PATCH {uri}: status {resp.status} {err[:250]}", file=sys.stderr)
        except Exception as e:
            print(f"  SecureBoot PATCH {uri}: {e}", file=sys.stderr)

    # 2. Try BIOS Attributes (attribute names and values vary by platform)
    bios_disable_attempts = [
        ("SecureBoot", "Disabled"),
        ("SecureBoot", "Disable"),
        ("SecureBootPolicy", "Disabled"),
        ("SecureBootEnforcement", "Disabled"),
        ("SecureBootEnforcement", "Disable"),
    ]
    for attr_name, attr_value in bios_disable_attempts:
        try:
            body = {"Attributes": {attr_name: attr_value}}
            resp = client.patch(BIOS_SETTINGS_URI, body)
            if resp.status in (200, 201, 202, 204):
                print(f"Secure Boot disabled via BIOS attribute {attr_name}={attr_value!r} (takes effect after reboot).")
                return True
            err = getattr(resp, "text", "") or ""
            if resp.status not in (400, 404, 405):
                print(f"  BIOS PATCH {attr_name}={attr_value!r}: status {resp.status} {err[:150]}", file=sys.stderr)
        except Exception as e:
            print(f"  BIOS PATCH {attr_name}: {e}", file=sys.stderr)

    print("Secure Boot disable failed: SecureBoot resource and BIOS attribute attempts did not succeed. Use --debug-secure-boot to inspect your iLO.", file=sys.stderr)
    return False


def _debug_secure_boot(client: Any) -> None:
    """GET SecureBoot and Bios resources and print state (for troubleshooting disable)."""
    for name, uri in [
        ("SecureBoot", SECURE_BOOT_URI),
        ("Bios (current)", BIOS_URI),
        ("Bios/Settings (pending)", BIOS_SETTINGS_URI),
    ]:
        try:
            resp = client.get(uri)
            data = getattr(resp, "dict", None) or getattr(resp, "data", None)
            text = getattr(resp, "text", "") or ""
            print(f"\n--- {name} GET {uri} (status {resp.status}) ---")
            if data is not None:
                out = {k: v for k, v in data.items() if k not in ("@odata.context", "Links")}
                print(json.dumps(out, indent=2, default=str)[:3000])
                if len(json.dumps(out, default=str)) > 3000:
                    print("... (truncated)")
            else:
                print(text[:800] if text else "(no body)")
        except Exception as e:
            print(f"Error: {e}")


def _normalize_cert_pem_for_compare(pem: str) -> str:
    """Normalize PEM for comparison: extract base64 body between BEGIN/END, no whitespace."""
    if not pem:
        return ""
    s = pem.replace("\r\n", "\n").replace("\r", "\n").strip()
    lines = s.split("\n")
    b64_parts: List[str] = []
    in_body = False
    for line in lines:
        line = line.strip()
        if line.startswith("-----BEGIN"):
            in_body = True
            continue
        if line.startswith("-----END"):
            break
        if in_body and line:
            b64_parts.append(line)
    return "".join(b64_parts).replace(" ", "")


def _cert_der_from_pem(pem: str) -> Optional[bytes]:
    """Extract DER bytes from PEM string. Returns None if invalid."""
    try:
        b64 = _normalize_cert_pem_for_compare(pem)
        if not b64:
            return None
        return base64.b64decode(b64)
    except Exception:
        return None


def _cert_sha256_fingerprint(pem: str) -> Optional[str]:
    """Return SHA-256 fingerprint of certificate (hex, lower). None if PEM invalid."""
    der = _cert_der_from_pem(pem)
    if not der:
        return None
    return hashlib.sha256(der).hexdigest().lower()


def _verify_cert_in_secure_boot_db(client: Any, cert_pem: str) -> bool:
    """GET db Certificates collection and check if our cert is enrolled. Match by CertificateString or SHA256 fingerprint (iLO often omits cert body in GET)."""
    try:
        resp = client.get(SECURE_BOOT_DB_CERTIFICATES_COLLECTION_URI)
        if resp.status != 200:
            return False
        data = getattr(resp, "dict", None) or getattr(resp, "data", None)
        if not data:
            return False
        members = data.get("Members") or []
        our_norm = _normalize_cert_pem_for_compare(cert_pem)
        our_fp = _cert_sha256_fingerprint(cert_pem)

        def _cert_matches(cert_data: Dict[str, Any]) -> bool:
            enrolled = (cert_data or {}).get("CertificateString") or ""
            if our_norm and enrolled and _normalize_cert_pem_for_compare(enrolled) == our_norm:
                return True
            for key in ("FingerprintHash", "Fingerprint", "fingerprint", "fingerprint_hash"):
                api_fp = (cert_data or {}).get(key)
                if not api_fp or not our_fp:
                    continue
                api_fp = str(api_fp).strip().lower()
                if ":" in api_fp:
                    api_fp = api_fp.split(":", 1)[-1].strip()
                api_fp = api_fp.replace(" ", "").replace(":", "")
                if api_fp == our_fp or our_fp.endswith(api_fp) or api_fp.endswith(our_fp):
                    return True
            return False

        for member in members:
            if isinstance(member, dict):
                if _cert_matches(member):
                    return True
                uri = member.get("@odata.id")
            elif isinstance(member, str):
                uri = member
            else:
                uri = None
            if not uri:
                continue
            try:
                cert_resp = client.get(uri)
                if cert_resp.status != 200:
                    continue
                cert_data = getattr(cert_resp, "dict", None) or getattr(cert_resp, "data", None) or {}
                if _cert_matches(cert_data):
                    return True
            except Exception:
                continue
        return False
    except Exception:
        return False


# iLO returns this when the Secure Boot db certificate limit is reached
SECURE_BOOT_DB_LIMIT_MESSAGE_IDS = ("CreateLimitReachedForResource", "Base.1.17.CreateLimitReachedForResource")


def _export_secure_boot_db_to_file(client: Any, output_path: str, ilo_ip: str = "") -> bool:
    """List Secure Boot db certificates and write to output_path as JSON. Returns True on success."""
    entries = _list_secure_boot_db_certificates(client)
    export = {"ilo_ip": ilo_ip, "certificates": [{"name": e.get("name") or "", "uri": e.get("uri") or "", "fingerprint": e.get("fingerprint")} for e in entries]}
    try:
        with open(output_path, "w", encoding=FILE_ENCODING) as f:
            json.dump(export, f, indent=2)
        return True
    except OSError:
        return False


def _list_secure_boot_db_certificates(client: Any) -> List[Dict[str, Any]]:
    """GET db Certificates collection and return list of { 'uri': str, 'name': str, 'fingerprint': str or None, 'data': dict }."""
    result = []
    try:
        resp = client.get(SECURE_BOOT_DB_CERTIFICATES_COLLECTION_URI)
        if resp.status != 200:
            return result
        data = getattr(resp, "dict", None) or getattr(resp, "data", None)
        if not data:
            return result
        members = data.get("Members") or []
        for member in members:
            uri = member.get("@odata.id") if isinstance(member, dict) else (member if isinstance(member, str) else None)
            if not uri:
                continue
            name = ""
            fp = None
            cert_data = {}
            try:
                cr = client.get(uri)
                if cr.status != 200:
                    result.append({"uri": uri, "name": "", "fingerprint": None, "data": {}})
                    continue
                cert_data = getattr(cr, "dict", None) or getattr(cr, "data", None) or {}
                name = (cert_data.get("Name") or cert_data.get("Description") or cert_data.get("Id") or "").strip()
                if not name and uri:
                    # Use last path segment for unnamed entries (e.g. ".../Certificates/17" -> "entry 17")
                    name = uri.rstrip("/").split("/")[-1] if "/" in uri else uri
                    try:
                        int(name)
                        name = f"(no name, id {name})"
                    except ValueError:
                        name = f"(no name, {name})"
                for key in ("FingerprintHash", "Fingerprint", "fingerprint", "fingerprint_hash"):
                    v = cert_data.get(key)
                    if v:
                        fp = str(v).strip().lower().replace(" ", "").replace(":", "")
                        break
            except Exception:
                pass
            result.append({"uri": uri, "name": name, "fingerprint": fp, "data": cert_data})
    except Exception:
        pass
    return result


def _is_nutanix_legacy_cert(entry: Dict[str, Any], our_fingerprint: Optional[str]) -> bool:
    """True if entry looks like an older Nutanix SB cert (v1/v2) that we can remove to make room for v3."""
    name = (entry.get("name") or "").lower()
    if "nutanix" not in name:
        return False
    # Do not remove the cert we're adding (match by fingerprint if we have it)
    fp = entry.get("fingerprint")
    if our_fingerprint and fp and (fp == our_fingerprint or our_fingerprint.endswith(fp) or fp.endswith(our_fingerprint)):
        return False
    # Prefer removing names that suggest v1/v2 (e.g. "Nutanix Secure Boot v1", "Nutanix v2")
    if "v3" in name or "version 3" in name:
        return False
    return True


def _delete_secure_boot_db_certificate(client: Any, uri: str) -> bool:
    """
    DELETE one certificate from the Secure Boot Authorized Signature Database (db).

    Redfish API (HPE):
      DELETE /redfish/v1/Systems/1/SecureBoot/SecureBootDatabases/{database_type}/Certificates/{Id}
    For db: DELETE .../SecureBootDatabases/db/Certificates/{Id}
    Response: 200 OK or 204 No Content. Reboot required after modifying Secure Boot databases.

    Constraints: iLO generally does not allow deletion from default/factory databases; only
    user-enrolled entries can be removed. Permissions: Configure Components or Administrator.

    Tries: client.delete(uri), _rest_request(uri, method='DELETE'), request(uri, method='DELETE'),
    then raw HTTP DELETE via requests if client exposes default_url and credentials.
    """
    for attempt in ("delete", "_rest_request", "request"):
        fn = getattr(client, attempt, None)
        if not callable(fn):
            continue
        try:
            if attempt == "delete":
                resp = fn(uri)
            else:
                resp = fn(uri, method="DELETE")
            status = getattr(resp, "status", None)
            if status in (200, 204):
                return True
        except Exception:
            pass
    # Fallback: raw DELETE via requests if client exposes base URL and auth
    try:
        import requests  # noqa: F401
        base = getattr(client, "default_url", None) or getattr(client, "root_url", None) or getattr(client, "host", None)
        if base and isinstance(uri, str) and uri.startswith("/"):
            url = (base.rstrip("/") + uri) if not uri.startswith("http") else uri
            user = getattr(client, "username", None) or getattr(client, "default_username", None)
            pwd = getattr(client, "password", None) or getattr(client, "default_password", None)
            verify = getattr(client, "default_verify_cert", True)
            kwargs = {"timeout": 30, "verify": verify}
            if user and pwd:
                kwargs["auth"] = (user, pwd)
            r = requests.delete(url, **kwargs)
            if r.status_code in (200, 204):
                return True
    except Exception:
        pass
    return False


def _try_remove_legacy_nutanix_certs(
    client: Any,
    cert_pem_to_add: str,
    already_prompted: bool = False,
    already_delete_failed: bool = False,
    non_interactive: bool = False,
) -> Tuple[int, bool, bool]:
    """
    When the db is full, remove older Nutanix certs (v1/v2) so v3 can be added.
    If no Nutanix v1/v2 certs are found, list all certs and ask the user which to delete (once per run).
    Returns (number of certs removed, whether we showed the list and prompted, whether a delete was attempted and failed).
    If already_delete_failed is True, skips all delete attempts and just prints the hint (no retry).
    If non_interactive is True, never prompt; print message and return (0, True, False) when manual choice would be needed.
    """
    if already_delete_failed:
        print("  Secure Boot db is still full (DELETE failed earlier). Remove a cert manually in iLO (Security → Secure Boot Configuration → Authorized Signatures) and re-run.", file=sys.stderr)
        return (0, False, True)

    our_fp = _cert_sha256_fingerprint(cert_pem_to_add)
    entries = _list_secure_boot_db_certificates(client)
    to_remove = [e for e in entries if _is_nutanix_legacy_cert(e, our_fp)]
    removed = 0
    delete_failed = False

    if to_remove:
        for entry in to_remove:
            uri = entry.get("uri")
            name = entry.get("name") or uri
            if _delete_secure_boot_db_certificate(client, uri):
                removed += 1
                print(f"  Removed legacy Nutanix cert from db: {name}", file=sys.stderr)
                logger.info("Removed legacy Nutanix cert from db: %s", name)
            else:
                print(f"  Could not remove cert {name} (DELETE not supported or failed).", file=sys.stderr)
                print("  Many HPE iLOs do not allow deleting Secure Boot db certs via API; use iLO web UI to remove certs.", file=sys.stderr)
                delete_failed = True
                break  # Do not try more deletes after first failure
        return (removed, False, delete_failed)

    # No Nutanix v1/v2 found; list all certs and ask user which to delete (only once per run)
    if not entries:
        print("  Secure Boot db is full but no certs could be listed.", file=sys.stderr)
        return (0, False, False)

    if already_prompted:
        print("  Secure Boot db is still full. Remove a cert manually in iLO (Security → Secure Boot Configuration → Authorized Signatures) and re-run.", file=sys.stderr)
        return (0, False, False)

    if non_interactive or not sys.stdin.isatty():
        print("  Secure Boot db is full; no legacy Nutanix certs to remove. Use iLO UI (Security → Secure Boot Configuration → Authorized Signatures) or re-run with an interactive terminal to choose a cert to delete.", file=sys.stderr)
        return (0, True, False)

    cert_list_max = 40
    print("  No Nutanix v1/v2 certs found. Current certificates in Secure Boot db (Authorized Signatures):", file=sys.stderr)
    if len(entries) > cert_list_max:
        print(
            f"  Showing first {cert_list_max} of {len(entries)} certs. Type 'all' at the prompt to show the full list.",
            file=sys.stderr,
        )
    entries_to_show = entries[:cert_list_max]
    for i, entry in enumerate(entries_to_show, 1):
        name = entry.get("name") or "(no name)"
        uri = entry.get("uri", "")
        print(f"    {i}. {name}", file=sys.stderr)
        logger.debug("Db cert %s: %s %s", i, name, uri)

    print("  If DELETE fails, remove certs manually in iLO: Security → Secure Boot Configuration → Authorized Signatures (db).", file=sys.stderr)
    try:
        while True:
            prompt = "  Enter number(s) to delete (e.g. 1 or 1,3), type 'all' to show full list, or 'q' to skip: "
            choice = input(prompt).strip().lower()
            if not choice or choice == "q":
                return (0, True, False)
            if choice == "all":
                for j, entry in enumerate(entries[cert_list_max:], cert_list_max + 1):
                    name = entry.get("name") or "(no name)"
                    uri = entry.get("uri", "")
                    print(f"    {j}. {name}", file=sys.stderr)
                    logger.debug("Db cert %s: %s %s", j, name, uri)
                continue
            break
        indices = []
        for part in choice.replace(",", " ").split():
            try:
                n = int(part)
                if 1 <= n <= len(entries):
                    indices.append(n - 1)
                else:
                    print(f"  Invalid number {n}; valid range 1-{len(entries)}.", file=sys.stderr)
            except ValueError:
                pass
        for idx in sorted(set(indices), reverse=True):
            entry = entries[idx]
            uri = entry.get("uri")
            name = entry.get("name") or uri
            if _delete_secure_boot_db_certificate(client, uri):
                removed += 1
                print(f"  Removed cert from db: {name}", file=sys.stderr)
                logger.info("Removed user-selected cert from db: %s", name)
            else:
                print(f"  Could not remove cert {name} (DELETE not supported or failed).", file=sys.stderr)
                print("  Many HPE iLOs do not allow deleting Secure Boot db certs via API; use iLO web UI to remove certs.", file=sys.stderr)
                delete_failed = True
                break  # Do not try more deletes after first failure
    except (EOFError, KeyboardInterrupt):
        print("  Skipped.", file=sys.stderr)
    return (removed, True, delete_failed)


# Secure Boot cert upload: single pass through all URI/body combinations (no retry loop)
SECURE_BOOT_CERT_RETRIES = 1
SECURE_BOOT_CERT_RETRY_DELAY_SEC = 2
# When True, try only the first URI + first body (one cert POST total); when False, try all URI/body combinations once each.
SECURE_BOOT_CERT_ONE_ATTEMPT = False
# After 202 Accepted, iLO may need time to persist; wait before first verification
SECURE_BOOT_CERT_VERIFY_INITIAL_DELAY_SEC = 4
SECURE_BOOT_CERT_VERIFY_RETRIES = 5


def _cert_accepted_but_not_verified_in_db(status: Optional[int]) -> bool:
    """
    Return False after cert POST succeeded (200/201/202/204) but _verify_cert_in_secure_boot_db
    never saw the cert. Do not treat this as success: 202 especially means async work may still be pending.
    """
    st = status if status is not None else "?"
    print(
        f"  HTTP {st}: upload accepted but certificate was NOT visible in the Secure Boot db after verification retries.",
        file=sys.stderr,
    )
    print(
        "  202 Accepted is asynchronous: the import may finish later or only after host reboot. "
        "Re-run after reboot or confirm in iLO (Security → Secure Boot → Authorized Signatures).",
        file=sys.stderr,
    )
    return False


def _pem_to_64_char_lines(pem: str) -> str:
    """Return PEM with base64 body wrapped to 64 chars per line (some iLOs require this)."""
    b64 = _normalize_cert_pem_for_compare(pem)
    if not b64:
        return pem.replace("\r\n", "\n").strip() + "\n"
    lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----\n"


def _extract_extended_info_msgs(obj: Any) -> Optional[str]:
    """From a Redfish error dict, find @Message.ExtendedInfo array and return ' | '.join(Message) or None."""
    if not isinstance(obj, dict):
        return None
    # Direct keys (error object or top-level)
    for key in ("@Message.ExtendedInfo", "Message.ExtendedInfo", "ExtendedInfo"):
        ext = obj.get(key)
        if isinstance(ext, list) and ext:
            parts = []
            for entry in ext:
                if isinstance(entry, dict):
                    msg = entry.get("Message") or entry.get("message") or entry.get("MessageId") or ""
                    if msg:
                        parts.append(str(msg).strip())
                elif isinstance(entry, str):
                    parts.append(entry.strip())
            if parts:
                return " | ".join(parts)[:600]
    # Recurse into error/Error
    for key in ("error", "Error"):
        sub = obj.get(key)
        if isinstance(sub, dict):
            out = _extract_extended_info_msgs(sub)
            if out:
                return out
    return None


def _cert_response_error_body(resp: Any) -> str:
    """Extract error body from a Redfish response for logging (400/404/405 etc). Parses @Message.ExtendedInfo when present."""
    # 1) Prefer resp.dict (ilorest often parses body here)
    data = getattr(resp, "dict", None) or getattr(resp, "data", None)
    if isinstance(data, dict):
        out = _extract_extended_info_msgs(data)
        if out:
            return out
        err = data.get("error") or data.get("Error")
        if isinstance(err, dict):
            for key in ("message", "Message", "description", "Description"):
                val = err.get(key)
                if isinstance(val, str) and "ExtendedInfo" not in val:
                    return val[:500]
    # 2) Full body from .text or .read()
    text = getattr(resp, "text", None) or ""
    if isinstance(text, bytes):
        text = text.decode("utf-8", errors="replace")
    raw = (text or "").strip()
    if getattr(resp, "read", None) and callable(resp.read) and (not raw or "ExtendedInfo" in raw):
        try:
            body = resp.read()
            if isinstance(body, bytes):
                body = body.decode("utf-8", errors="replace")
            raw = (body or "").strip() or raw
        except Exception:
            pass
    if raw and (raw.startswith("{") or "ExtendedInfo" in raw):
        try:
            data = json.loads(raw)
            out = _extract_extended_info_msgs(data)
            if out:
                return out
            err = data.get("error") or data.get("Error") or data
            if isinstance(err, dict):
                msg = err.get("message") or err.get("Message")
                if isinstance(msg, str) and "ExtendedInfo" not in msg:
                    return msg[:500]
        except (json.JSONDecodeError, TypeError):
            pass
    if raw:
        return raw[:500]
    return ""


def _import_secure_boot_cert(
    client: Any,
    cert_pem: str,
    non_interactive: bool = False,
    *,
    verify_initial_delay_sec: Optional[float] = None,
    verify_retry_delay_sec: Optional[float] = None,
    verify_retries: Optional[int] = None,
) -> bool:
    """POST certificate to Secure Boot Authorized Signature Database (db). Tries multiple URIs and payload formats. Returns True on success or if cert already in db. BIOS must be in User mode."""
    init_sec = float(
        verify_initial_delay_sec if verify_initial_delay_sec is not None else SECURE_BOOT_CERT_VERIFY_INITIAL_DELAY_SEC
    )
    retry_sec = float(verify_retry_delay_sec if verify_retry_delay_sec is not None else SECURE_BOOT_CERT_RETRY_DELAY_SEC)
    n_verify = int(verify_retries if verify_retries is not None else SECURE_BOOT_CERT_VERIFY_RETRIES)
    # Idempotent: skip POST if cert is already in db (by fingerprint)
    if _verify_cert_in_secure_boot_db(client, cert_pem):
        print("Certificate already in Secure Boot db; no change needed.")
        return True
    logger.info("Secure Boot cert import: single pass over URIs and payload formats.")
    # Normalize: CRLF -> LF, 64-char lines for base64 (some iLOs require), trailing newline (per HPE doc)
    cert_string = _pem_to_64_char_lines(cert_pem)
    # Base64-only (no PEM headers) for variants that expect it
    b64_only = _normalize_cert_pem_for_compare(cert_pem)
    # Existing URIs (unchanged order – known to work on many iLOs)
    uris_to_try = [
        SECURE_BOOT_DB_CERTIFICATES_URI,
        "/redfish/v1/Systems/1/SecureBoot/SecureBootDatabases/db/Certificates",
        SECURE_BOOT_DB_CERTIFICATES_PAYLOAD_URI,
    ]
    # Existing bodies (unchanged order)
    bodies_to_try = [
        {"CertificateString": cert_string, "CertificateType": "PEM"},
        {"Certificate": cert_string},
        {"CertificateString": cert_string, "CertificateType": "x509"},
        {"CertificateString": b64_only, "CertificateType": "Base64"},
    ]
    # Additional payload variants for other iLO/Redfish implementations (tried after the above)
    bodies_extra = [
        {"CertificateString": cert_string},  # no CertificateType
        {"Certificate": cert_string, "CertificateType": "PEM"},
        {"Certificate": cert_string, "CertificateType": "x509"},
        {"Certificate": b64_only, "CertificateType": "Base64"},
        {"CertificateString": cert_string, "CertificateType": "X509"},
        {"CertificateString": cert_string, "CertificateType": "x509 PEM"},
        {"CertificateString": b64_only},
        {"Body": cert_string},
        {"CertificateString": cert_string, "CertificateEncoding": "PEM"},
        {"Certificate": cert_string, "Encoding": "PEM"},
        {"Cert": cert_string},
        {"CertificateString": cert_string, "CertificateType": "DER"},
        {"CertificateBytes": b64_only},
    ]
    last_err = None
    cert_removal_prompted = False  # Only prompt once per run when db is full and no legacy Nutanix certs
    cert_delete_failed = False  # Once a delete fails, do not retry delete (skip further delete attempts)
    for attempt in range(1, SECURE_BOOT_CERT_RETRIES + 1):
        try:
            # Try existing URIs with existing bodies first (no change to current behavior)
            for uri in uris_to_try:
                for body in bodies_to_try:
                    try:
                        resp = client.post(uri, body)
                    except Exception as e:
                        last_err = str(e)
                        continue
                    status = getattr(resp, "status", None)
                    resp_text = _cert_response_error_body(resp) or (getattr(resp, "text", None) or "").strip()[:400]
                    logger.debug("Cert POST uri=%s body_keys=%s status=%s resp=%s", uri, list(body.keys()), status, (resp_text[:200] if resp_text else ""))
                    if status in (200, 201, 202, 204):
                        logger.info("Cert accepted: status=%s", status)
                        print("Secure Boot certificate accepted by iLO (import to Authorized Signature Database).")
                        time.sleep(init_sec)
                        for v in range(n_verify):
                            if _verify_cert_in_secure_boot_db(client, cert_pem):
                                print("Certificate verified: present in iLO Secure Boot db.")
                                return True
                            if v < n_verify - 1:
                                time.sleep(retry_sec)
                        return _cert_accepted_but_not_verified_in_db(status)
                    if status and 400 <= status < 500:
                        if not any(mid in (resp_text or "") for mid in SECURE_BOOT_DB_LIMIT_MESSAGE_IDS):
                            time.sleep(1)
                        if _verify_cert_in_secure_boot_db(client, cert_pem):
                            print("Certificate already in db; verified present.")
                            return True
                        last_err = f"status {status}" + (f" {resp_text}" if resp_text else "")
                        logger.debug("Cert POST 4xx: %s %s", uri, last_err)
                        # If db limit reached, try removing legacy Nutanix certs (v1/v2) then retry once
                        if any(mid in (resp_text or "") for mid in SECURE_BOOT_DB_LIMIT_MESSAGE_IDS):
                            removed, prompted, delete_failed = _try_remove_legacy_nutanix_certs(
                                client, cert_pem, cert_removal_prompted, cert_delete_failed, non_interactive
                            )
                            cert_removal_prompted = cert_removal_prompted or prompted
                            cert_delete_failed = cert_delete_failed or delete_failed
                            if cert_delete_failed:
                                print(
                                    "Secure Boot db is still full (DELETE failed earlier). Skipping further cert POST attempts.",
                                    file=sys.stderr,
                                )
                                return False
                            if removed > 0:
                                try:
                                    resp2 = client.post(uri, body)
                                    st2 = getattr(resp2, "status", None)
                                    if st2 in (200, 201, 202, 204):
                                        logger.info("Cert accepted after removing legacy certs: status=%s", st2)
                                        print("Secure Boot certificate accepted by iLO (import to Authorized Signature Database).")
                                        time.sleep(init_sec)
                                        for v in range(n_verify):
                                            if _verify_cert_in_secure_boot_db(client, cert_pem):
                                                print("Certificate verified: present in iLO Secure Boot db.")
                                                return True
                                            if v < n_verify - 1:
                                                time.sleep(retry_sec)
                                        return _cert_accepted_but_not_verified_in_db(st2)
                                except Exception:
                                    pass
                        print(f"  Cert POST {uri}: {last_err}", file=sys.stderr)
                        if SECURE_BOOT_CERT_ONE_ATTEMPT:
                            break
                        continue
                    last_err = f"status {status}" + (f" {resp_text}" if resp_text else "")
                    logger.debug("Cert POST fail: %s %s", uri, last_err)
                    print(f"  Cert POST {uri}: {last_err}", file=sys.stderr)
                    if SECURE_BOOT_CERT_ONE_ATTEMPT:
                        break
                if SECURE_BOOT_CERT_ONE_ATTEMPT:
                    break
            # Then try extra URIs with existing bodies (skipped when SECURE_BOOT_CERT_ONE_ATTEMPT)
            if not SECURE_BOOT_CERT_ONE_ATTEMPT:
                for uri in SECURE_BOOT_CERT_POST_URIS_EXTRA:
                    for body in bodies_to_try:
                        try:
                            resp = client.post(uri, body)
                        except Exception as e:
                            last_err = str(e)
                            continue
                        status = getattr(resp, "status", None)
                        resp_text = _cert_response_error_body(resp) or (getattr(resp, "text", None) or "").strip()[:400]
                        logger.debug("Cert POST (extra URI) uri=%s body_keys=%s status=%s resp=%s", uri, list(body.keys()), status, (resp_text[:200] if resp_text else ""))
                        if status in (200, 201, 202, 204):
                            logger.info("Cert accepted: status=%s", status)
                            print("Secure Boot certificate accepted by iLO (import to Authorized Signature Database).")
                            time.sleep(init_sec)
                            for v in range(n_verify):
                                if _verify_cert_in_secure_boot_db(client, cert_pem):
                                    print("Certificate verified: present in iLO Secure Boot db.")
                                    return True
                                if v < n_verify - 1:
                                    time.sleep(retry_sec)
                            return _cert_accepted_but_not_verified_in_db(status)
                        if status and 400 <= status < 500:
                            if not any(mid in (resp_text or "") for mid in SECURE_BOOT_DB_LIMIT_MESSAGE_IDS):
                                time.sleep(1)
                            if _verify_cert_in_secure_boot_db(client, cert_pem):
                                print("Certificate already in db; verified present.")
                                return True
                            last_err = f"status {status}" + (f" {resp_text}" if resp_text else "")
                            if any(mid in (resp_text or "") for mid in SECURE_BOOT_DB_LIMIT_MESSAGE_IDS):
                                removed, prompted, delete_failed = _try_remove_legacy_nutanix_certs(
                                    client, cert_pem, cert_removal_prompted, cert_delete_failed, non_interactive
                                )
                                cert_removal_prompted = cert_removal_prompted or prompted
                                cert_delete_failed = cert_delete_failed or delete_failed
                                if cert_delete_failed:
                                    print(
                                        "Secure Boot db is still full (DELETE failed earlier). Skipping further cert POST attempts.",
                                        file=sys.stderr,
                                    )
                                    return False
                                if removed > 0:
                                    try:
                                        resp2 = client.post(uri, body)
                                        st2 = getattr(resp2, "status", None)
                                        if st2 in (200, 201, 202, 204):
                                            print("Secure Boot certificate accepted by iLO (import to Authorized Signature Database).")
                                            time.sleep(init_sec)
                                            for v in range(n_verify):
                                                if _verify_cert_in_secure_boot_db(client, cert_pem):
                                                    print("Certificate verified: present in iLO Secure Boot db.")
                                                    return True
                                                if v < n_verify - 1:
                                                    time.sleep(retry_sec)
                                            return _cert_accepted_but_not_verified_in_db(st2)
                                    except Exception:
                                        pass
                            print(f"  Cert POST {uri}: {last_err}", file=sys.stderr)
                            continue
                        last_err = f"status {status}" + (f" {resp_text}" if resp_text else "")
                        print(f"  Cert POST {uri}: {last_err}", file=sys.stderr)
                # Then try all URIs with extra body variants
                all_uris = uris_to_try + SECURE_BOOT_CERT_POST_URIS_EXTRA
                for uri in all_uris:
                    for body in bodies_extra:
                        try:
                            resp = client.post(uri, body)
                        except Exception as e:
                            last_err = str(e)
                            continue
                        status = getattr(resp, "status", None)
                        resp_text = _cert_response_error_body(resp) or (getattr(resp, "text", None) or "").strip()[:400]
                        logger.debug("Cert POST (extra body) uri=%s body_keys=%s status=%s resp=%s", uri, list(body.keys()), status, (resp_text[:200] if resp_text else ""))
                        if status in (200, 201, 202, 204):
                            logger.info("Cert accepted: status=%s", status)
                            print("Secure Boot certificate accepted by iLO (import to Authorized Signature Database).")
                            time.sleep(init_sec)
                            for v in range(n_verify):
                                if _verify_cert_in_secure_boot_db(client, cert_pem):
                                    print("Certificate verified: present in iLO Secure Boot db.")
                                    return True
                                if v < n_verify - 1:
                                    time.sleep(retry_sec)
                            return _cert_accepted_but_not_verified_in_db(status)
                        if status and 400 <= status < 500:
                            if not any(mid in (resp_text or "") for mid in SECURE_BOOT_DB_LIMIT_MESSAGE_IDS):
                                time.sleep(1)
                            if _verify_cert_in_secure_boot_db(client, cert_pem):
                                print("Certificate already in db; verified present.")
                                return True
                            last_err = f"status {status}" + (f" {resp_text}" if resp_text else "")
                            if any(mid in (resp_text or "") for mid in SECURE_BOOT_DB_LIMIT_MESSAGE_IDS):
                                removed, prompted, delete_failed = _try_remove_legacy_nutanix_certs(
                                    client, cert_pem, cert_removal_prompted, cert_delete_failed, non_interactive
                                )
                                cert_removal_prompted = cert_removal_prompted or prompted
                                cert_delete_failed = cert_delete_failed or delete_failed
                                if cert_delete_failed:
                                    print(
                                        "Secure Boot db is still full (DELETE failed earlier). Skipping further cert POST attempts.",
                                        file=sys.stderr,
                                    )
                                    return False
                                if removed > 0:
                                    try:
                                        resp2 = client.post(uri, body)
                                        st2 = getattr(resp2, "status", None)
                                        if st2 in (200, 201, 202, 204):
                                            print("Secure Boot certificate accepted by iLO (import to Authorized Signature Database).")
                                            time.sleep(init_sec)
                                            for v in range(n_verify):
                                                if _verify_cert_in_secure_boot_db(client, cert_pem):
                                                    print("Certificate verified: present in iLO Secure Boot db.")
                                                    return True
                                                if v < n_verify - 1:
                                                    time.sleep(retry_sec)
                                            return _cert_accepted_but_not_verified_in_db(st2)
                                    except Exception:
                                        pass
                            print(f"  Cert POST {uri}: {last_err}", file=sys.stderr)
                            continue
                        last_err = f"status {status}" + (f" {resp_text}" if resp_text else "")
                        print(f"  Cert POST {uri}: {last_err}", file=sys.stderr)
            if attempt < SECURE_BOOT_CERT_RETRIES:
                print(f"  Cert upload attempt {attempt}/{SECURE_BOOT_CERT_RETRIES} failed; retrying in {SECURE_BOOT_CERT_RETRY_DELAY_SEC}s ...", file=sys.stderr)
                time.sleep(SECURE_BOOT_CERT_RETRY_DELAY_SEC)
        except Exception as e:
            last_err = str(e)
            if attempt < SECURE_BOOT_CERT_RETRIES:
                print(f"  Cert upload attempt {attempt}/{SECURE_BOOT_CERT_RETRIES} failed: {e}; retrying ...", file=sys.stderr)
                time.sleep(SECURE_BOOT_CERT_RETRY_DELAY_SEC)
            else:
                print(f"Secure Boot cert import failed: {e}", file=sys.stderr)
                return False
    if last_err:
        print(f"Secure Boot cert import failed: {last_err}", file=sys.stderr)
    return False


def set_bios(
    ilo_ip: str,
    username: str,
    password: str,
    timeout: int = DEFAULT_TIMEOUT,
    verify_ssl: bool = True,
    prompt_reboot: bool = True,
    yes_reboot: bool = False,
    skip_reboot: bool = False,
    non_interactive: bool = False,
    attribute_overrides: Optional[Dict[str, str]] = None,
    always_apply_keys: Optional[Iterable[str]] = None,
    cert_pem: Optional[str] = None,
    enable_secure_boot_resource: bool = False,
    disable_secure_boot_resource: bool = False,
    desired_from_file: Optional[Dict[str, str]] = None,
    file_metadata: Optional[Dict[str, str]] = None,
    match_model_cpu: bool = False,
    profile_name: Optional[str] = None,
    cert_verify_initial_delay_sec: Optional[float] = None,
    cert_verify_retry_delay_sec: Optional[float] = None,
    cert_verify_retries: Optional[int] = None,
) -> Tuple[int, Optional[Any]]:
    """
    Connect to iLO, compare current BIOS with desired, PATCH only differences,
    confirm pending settings, and optionally prompt for reboot.
    If desired_from_file is set, use it as the desired attributes (with optional
    file_metadata + match_model_cpu to skip BIOS apply when server model/CPU does not match).
    Returns (exit_code: 0 success, 1 error, 2 usage), and RedfishClient for reboot if needed.
    """
    client = None
    try:
        kwargs = {
            "base_url": f"https://{ilo_ip}",
            "username": username,
            "password": password,
            "timeout": timeout,
        }
        if not verify_ssl:
            kwargs["default_verify_cert"] = False
        try:
            client = RedfishClient(**kwargs)
        except TypeError:
            kwargs.pop("default_verify_cert", None)
            client = RedfishClient(**kwargs)
        client.login()

        model, cpu_vendor, cpu_model = _get_system_model_cpu(client)
        is_amd = cpu_vendor == "AMD"

        if desired_from_file is not None:
            if match_model_cpu and file_metadata:
                file_model = (file_metadata.get("Model") or "").strip()
                file_cpu = (file_metadata.get("CPU") or "").strip().upper()
                if file_model and file_model != "Unknown" and model != "Unknown":
                    if file_model not in model and model not in file_model:
                        print(f"Server model '{model}' does not match profile model '{file_model}'; skipping BIOS apply.")
                        desired = {}
                    elif file_cpu and file_cpu not in cpu_vendor.upper():
                        print(f"Server CPU '{cpu_vendor}' does not match profile CPU '{file_metadata.get('CPU')}'; skipping BIOS apply.")
                        desired = {}
                    else:
                        desired = dict(desired_from_file)
                else:
                    desired = dict(desired_from_file)
            else:
                desired = dict(desired_from_file)
        else:
            # No file/profile given: select by model so Gen10 gets Gen10 profile, Gen11 gets Gen11
            auto_profile = _profile_for_model(model, is_amd)
            if auto_profile:
                attrs, _ = _load_profile_by_name(auto_profile)
                if attrs:
                    desired = dict(attrs)
                    profile_name = auto_profile
                elif not desired:
                    print(f"Warning: Model-matched profile '{auto_profile}' not found or empty; using default by CPU.", file=sys.stderr)
            if not desired:
                desired = _get_desired_attributes(is_amd)

        if attribute_overrides:
            desired = {**desired, **attribute_overrides}

        display_profile = profile_name
        if display_profile is None and desired:
            display_profile = DEFAULT_AMD_PROFILE if is_amd else DEFAULT_INTEL_PROFILE
        elif display_profile is None:
            display_profile = "(none)"

        display_model = _model_display_name(model)
        print(f"Detected model: {display_model}  CPU: {cpu_vendor} ({cpu_model})")
        if desired:
            print(f"Profile: {display_profile} ({len(desired)} attributes)")
        else:
            print("Profile: (none) – Secure Boot/cert/reboot only if requested")
        print()

        # 1. Current BIOS (active) – only if we have desired attributes
        current = _get_attributes(client, BIOS_URI) if desired else {}
        if desired:
            print("Current BIOS (active) – relevant attributes:")
            for key in desired:
                val = current.get(key, "<not reported>")
                print(f"  {key}: {val}")
            print()

        # 2. Idempotent: only attributes that differ; include optional extra keys (e.g. Secure Boot)
        to_set = _attributes_to_change(desired, current) if desired else {}
        if always_apply_keys:
            for key in always_apply_keys:
                if key in desired:
                    to_set[key] = desired[key]
        if not to_set:
            print("All requested BIOS settings already match. No changes needed (idempotent).")
            if disable_secure_boot_resource:
                _disable_secure_boot_resource(client)
            elif enable_secure_boot_resource:
                _enable_secure_boot_resource(client)
            if cert_pem:
                print("Note: Certificate enrollment requires BIOS/Platform to be in User mode.")
                cert_ok = _import_secure_boot_cert(
                    client,
                    cert_pem,
                    non_interactive,
                    verify_initial_delay_sec=cert_verify_initial_delay_sec,
                    verify_retry_delay_sec=cert_verify_retry_delay_sec,
                    verify_retries=cert_verify_retries,
                )
                if not cert_ok:
                    print("Error: Secure Boot certificate enrollment failed; skipping server.", file=sys.stderr)
                    return 1, client
            if not skip_reboot and yes_reboot:
                _do_reset(client)
            elif not skip_reboot and prompt_reboot and sys.stdin.isatty():
                print("For nodes in a Nutanix cluster with workloads, consider: rolling_restart -h (on CVM).")
                r = input("Reboot server anyway (iLO Reset)? [y/N]: ").strip().lower()
                if r == "y" or r == "yes":
                    _do_reset(client)
            return 0, client

        print("Attributes to set (differ from current):")
        for k, v in to_set.items():
            print(f"  {k}: {v}")
        print()

        body = {"Attributes": to_set}
        resp = client.patch(BIOS_SETTINGS_URI, body)
        if resp.status not in (200, 204):
            return 1, None

        print("BIOS settings updated successfully (pending until reboot).")
        print()

        # 2b. Enable or disable Secure Boot via Redfish SecureBoot resource (takes effect after reboot)
        if disable_secure_boot_resource:
            _disable_secure_boot_resource(client)
        elif enable_secure_boot_resource:
            _enable_secure_boot_resource(client)

        # 3. Import certificate to Secure Boot db if requested (BIOS must be in User mode)
        if cert_pem:
            print("Note: Certificate enrollment requires BIOS/Platform to be in User mode.")
            cert_ok = _import_secure_boot_cert(
                client,
                cert_pem,
                non_interactive,
                verify_initial_delay_sec=cert_verify_initial_delay_sec,
                verify_retry_delay_sec=cert_verify_retry_delay_sec,
                verify_retries=cert_verify_retries,
            )
            if not cert_ok:
                print("Error: Secure Boot certificate enrollment failed; skipping server.", file=sys.stderr)
                return 1, client

        # 4. Confirm: read back pending Settings
        pending = _get_attributes(client, BIOS_SETTINGS_URI)
        print("Pending BIOS (Settings) – confirmation:")
        for key in desired:
            val = pending.get(key, "<not reported>")
            print(f"  {key}: {val}")
        print()

        # 5. Reboot prompt (or --reboot when multi: no prompt, but still reboot if requested)
        if not skip_reboot and prompt_reboot:
            if yes_reboot:
                _do_reset(client)
            elif sys.stdin.isatty():
                print("For nodes in a Nutanix cluster with workloads, consider: rolling_restart -h (on CVM).")
                r = input("Reboot server now (iLO Reset) to apply BIOS changes? [y/N]: ").strip().lower()
                if r == "y" or r == "yes":
                    _do_reset(client)
                else:
                    print("Skipped reboot. Changes will take effect on next manual reboot.")
            else:
                print("Non-interactive: skipped reboot prompt. Use --reboot to reboot, or reboot manually.")
        elif not skip_reboot and yes_reboot:
            _do_reset(client)

        return 0, client
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1, None
    finally:
        if client is not None:
            try:
                client.logout()
            except Exception:
                pass


def check_bios(
    ilo_ip: str,
    username: str,
    password: str,
    timeout: int = DEFAULT_TIMEOUT,
    verify_ssl: bool = True,
    extra_desired: Optional[Dict[str, str]] = None,
    cert_pem: Optional[str] = None,
    base_desired: Optional[Dict[str, str]] = None,
    profile_name: Optional[str] = None,
    bios_diff: bool = False,
    output_format: str = "text",
) -> int:
    """
    Connect to iLO, detect CPU type, get current BIOS and desired profile,
    print comparison (current vs desired) and return 0 if all match, 1 if any differ.
    If base_desired is provided (e.g. from file), use it as the base; else use built-in by CPU.
    If cert_pem is provided, also checks whether that certificate is enrolled in Secure Boot db.
    bios_diff: if True, only print attributes that differ. output_format: "text" or "json".
    No PATCH or reboot; read-only.
    """
    client = None
    try:
        kwargs = {
            "base_url": f"https://{ilo_ip}",
            "username": username,
            "password": password,
            "timeout": timeout,
        }
        if not verify_ssl:
            kwargs["default_verify_cert"] = False
        try:
            client = RedfishClient(**kwargs)
        except TypeError:
            kwargs.pop("default_verify_cert", None)
            client = RedfishClient(**kwargs)
        client.login()

        is_amd = _is_amd_processor(client)
        model, cpu_vendor, cpu_model = _get_system_model_cpu(client)
        if base_desired is not None:
            desired = dict(base_desired)
        else:
            auto_profile = _profile_for_model(model, is_amd)
            if auto_profile:
                attrs, _ = _load_profile_by_name(auto_profile)
                if attrs:
                    desired = dict(attrs)
                else:
                    print(f"Warning: Model-matched profile '{auto_profile}' not found or empty; using default by CPU.", file=sys.stderr)
                    desired = _get_desired_attributes(is_amd)
            else:
                desired = _get_desired_attributes(is_amd)
        if extra_desired:
            desired = {**desired, **extra_desired}
        current = _get_attributes(client, BIOS_URI)

        display_profile = profile_name
        if display_profile is None:
            display_profile = _profile_for_model(model, is_amd) or (DEFAULT_AMD_PROFILE if is_amd else DEFAULT_INTEL_PROFILE)
        display_model = _model_display_name(model)
        print(f"Detected model: {display_model}  CPU: {cpu_vendor} ({cpu_model})")
        print(f"Profile: {display_profile}")
        print()

        # When checking Secure Boot, also GET the SecureBoot resource (actual state, not just BIOS attributes)
        if extra_desired and ("SecureBoot" in extra_desired or "SecureBootEnable" in str(extra_desired)):
            try:
                sb_resp = client.get(SECURE_BOOT_URI)
                if sb_resp.status == 200:
                    sb_data = getattr(sb_resp, "dict", None) or getattr(sb_resp, "data", None) or {}
                    current["SecureBootEnable"] = sb_data.get("SecureBootEnable")
                    if "SecureBootMode" in sb_data:
                        current["SecureBootMode"] = sb_data.get("SecureBootMode")
                    desired.setdefault("SecureBootEnable", True)
                    if "SecureBootMode" not in desired and sb_data.get("SecureBootMode") is not None:
                        desired.setdefault("SecureBootMode", "Standard")
                else:
                    current["SecureBootEnable"] = "<not reported>"
            except Exception:
                current["SecureBootEnable"] = "<error reading>"
            # BIOS GET often does not include SecureBoot string; comparison uses SecureBootEnable from resource only
            desired.pop("SecureBoot", None)

        # Build list of (key, cur_str, want_str, match) for optional filtering and JSON
        rows: List[Tuple[str, str, str, bool]] = []
        all_match = True
        if output_format != "json":
            if bios_diff:
                print("Attributes that differ from desired profile:")
                print(f"{'Attribute':<35} {'Current':<28} {'Desired':<28}")
                print("-" * 92)
            else:
                print(f"{'Attribute':<35} {'Current':<28} {'Desired':<28} {'Match'}")
                print("-" * 95)
        for key in sorted(desired.keys()):
            cur = current.get(key)
            cur_str = str(cur) if cur is not None else "<not set>"
            want = desired[key]
            # VMD port keys: if iLO does not report the attribute (port not present on platform), treat as N/A not DIFF
            if key.startswith("Vmdon") and cur is None:
                rows.append((key, cur_str[:27], str(want)[:27], True))  # N/A counts as match for display
                if not bios_diff and output_format != "json":
                    print(f"{key:<35} {cur_str[:27]:<28} {str(want)[:27]:<28} {'N/A'}")
                continue
            match = cur is not None and str(cur).strip() == str(want).strip()
            if not match:
                all_match = False
            rows.append((key, cur_str[:27], str(want)[:27], match))
            if output_format != "json" and (not bios_diff or not match):
                if bios_diff:
                    print(f"{key:<35} {cur_str[:27]:<28} {str(want)[:27]:<28}")
                else:
                    status = "OK" if match else "DIFF"
                    print(f"{key:<35} {cur_str[:27]:<28} {str(want)[:27]:<28} {status}")

        # Check if certificate (file) is enrolled in Secure Boot db
        cert_enrolled: Optional[bool] = None
        if cert_pem:
            cert_enrolled = _verify_cert_in_secure_boot_db(client, cert_pem)
            if not cert_enrolled:
                all_match = False

        if output_format == "json":
            diffs = [{"attribute": r[0], "current": r[1], "desired": r[2]} for r in rows if not r[3]]
            out = {
                "ilo_ip": ilo_ip,
                "model": display_model,
                "profile": display_profile,
                "all_match": all_match,
                "cert_enrolled_in_db": cert_enrolled,
                "diffs": diffs,
            }
            print(json.dumps(out, indent=2))
        else:
            if not bios_diff:
                print()
            if all_match:
                print("All BIOS settings match the desired profile.")
            else:
                print("One or more BIOS settings differ from the desired profile.")
            if cert_pem is not None:
                print(f"Certificate (file) enrolled in Secure Boot db: {'Yes' if cert_enrolled else 'No'}")

        return 0 if all_match else 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    finally:
        if client is not None:
            try:
                client.logout()
            except Exception:
                pass


def _do_reset(client: Any) -> None:
    """POST ComputerSystem.Reset with GracefulRestart (clean shutdown then reboot)."""
    try:
        body = {"ResetType": "GracefulRestart"}
        resp = client.post(SYSTEM_RESET_URI, body)
        if resp.status in (200, 204):
            print("Reset (GracefulRestart) sent. Server is rebooting.")
        else:
            err_detail = ""
            if hasattr(resp, "text") and resp.text:
                err_detail = f" Response: {resp.text[:500]}"
            elif hasattr(resp, "read") and callable(resp.read):
                try:
                    err_detail = f" Response: {resp.read()[:500]}"
                except Exception:
                    pass
            print(f"Reset request returned status {resp.status}. Check iLO.{err_detail}", file=sys.stderr)
    except Exception as e:
        print(f"Reset failed: {e}", file=sys.stderr)


def _reset_bios_to_default(client: Any) -> bool:
    """POST Bios.ResetBios to restore BIOS settings to factory default. Returns True on success. Reboot required for changes to take effect."""
    uris_to_try = [
        BIOS_RESET_TO_DEFAULT_URI,
        "/redfish/v1/Systems/1/Bios/Actions/Bios.ResetBios",
        "/redfish/v1/systems/1/bios/Actions/Bios.ResetBios/",
    ]
    body = {}
    last_err = None
    for uri in uris_to_try:
        try:
            resp = client.post(uri, body)
            if resp.status in (200, 204, 202):
                print("BIOS reset to default requested successfully. Reboot the server for changes to take effect.")
                return True
            last_err = f"status {resp.status}"
            if hasattr(resp, "text") and resp.text:
                last_err += f" {resp.text[:300]}"
        except Exception as e:
            last_err = str(e)
    print(f"BIOS reset to default failed: {last_err}", file=sys.stderr)
    return False


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="hpe-set-bios",
        description="Set HPE node BIOS via iLO Redfish (production-ready, idempotent). BIOS is optional: use built-in profile, --bios-settings-file, or --no-bios.",
        epilog="Examples: --check (compare only); --list-profiles (show profiles); -f ips.txt -p 'pw' (apply); -f ips.txt --no-bios --secure-boot-cert cert.cer --skip-reboot (cert only, no reboot); --fetch-bios-settings out.txt --no-write (print BIOS export).",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "ilo_ip",
        nargs="*",
        help="One or more iLO IP addresses or hostnames (or use -f/--file)",
    )
    parser.add_argument(
        "-f", "--file",
        nargs="?",
        const=DEFAULT_INPUT_FILE,
        default=None,
        metavar="PATH",
        help=f"File with one target per line: IP, or 'IP password', or 'IP user password' (space/comma); missing user/password use -u/-p. -f alone uses {DEFAULT_INPUT_FILE}",
    )
    parser.add_argument("-u", "--user", "--username", dest="user", default=DEFAULT_USERNAME, metavar="USER", help=f"iLO username (default: {DEFAULT_USERNAME})")
    parser.add_argument("-p", "--password", default=DEFAULT_PASSWORD, help="iLO password (default: ILO_PASSWORD env). Use -p - to read from stdin. Default for targets in -f file that have no password on their line.")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help=f"Timeout in seconds for API calls (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("--probe-timeout", type=int, default=PROBE_TIMEOUT, metavar="SEC", help=f"Timeout for iLO alive probe in seconds (default: {PROBE_TIMEOUT})")
    parser.add_argument("--no-verify-ssl", action="store_true", help="Disable SSL certificate verification")
    parser.add_argument("--log-file", metavar="FILE", default=None, help="Append log messages to FILE (INFO level). Use with --verbose for DEBUG.")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose (DEBUG) logging. Use with --log-file to capture details.")
    parser.add_argument("--check", action="store_true", help="Compare current BIOS to desired profile (no changes); exit 0 if match, 1 if differ")
    parser.add_argument("--dry-run", action="store_true", help="Only print desired attributes; do not connect or PATCH")
    parser.add_argument("--no-reboot-prompt", action="store_true", help="Do not ask to reboot server after applying settings")
    parser.add_argument("--reboot", action="store_true", help="Reboot server after applying settings (no prompt)")
    parser.add_argument("--skip-reboot", action="store_true", help="Never reboot (apply only). Use with automation or when rebooting via other means (e.g. rolling_restart).")
    parser.add_argument(
        "--reset-bios-to-default",
        action="store_true",
        help="Reset BIOS settings to factory default (no profile apply). Use --reboot to reboot after reset. Reboot required for changes to take effect.",
    )
    sb_group = parser.add_mutually_exclusive_group()
    sb_group.add_argument(
        "--enable-secure-boot",
        action="store_true",
        help="Set Secure Boot enabled (Enforcement=Enabled, Mode=Standard). Reboot required.",
    )
    sb_group.add_argument(
        "--disable-secure-boot",
        action="store_true",
        help="Set Secure Boot disabled via Redfish SecureBoot resource. Reboot required.",
    )
    parser.add_argument(
        "--secure-boot-cert",
        metavar="FILE",
        default=None,
        help="Import certificate into Secure Boot Authorized Signature Database (db). e.g. Nutanix_Secure_Boot_v3.cer (PEM or DER). BIOS must be in User mode.",
    )
    parser.add_argument(
        "--cert-verify-initial-delay",
        type=float,
        default=None,
        metavar="SEC",
        help=f"After cert POST (200/202), wait this many seconds before first db verification (default: {SECURE_BOOT_CERT_VERIFY_INITIAL_DELAY_SEC}). Use higher values for slow/async iLO.",
    )
    parser.add_argument(
        "--cert-verify-retry-delay",
        type=float,
        default=None,
        metavar="SEC",
        help=f"Seconds between db verification retries (default: {SECURE_BOOT_CERT_RETRY_DELAY_SEC}).",
    )
    parser.add_argument(
        "--cert-verify-retries",
        type=int,
        default=None,
        metavar="N",
        help=f"How many times to poll the Secure Boot db for the cert after POST (default: {SECURE_BOOT_CERT_VERIFY_RETRIES}).",
    )
    parser.add_argument(
        "--cert-db-export",
        metavar="FILE",
        default=None,
        help="Export Secure Boot db certificate list (names, URIs, fingerprints) to JSON file. No BIOS apply.",
    )
    parser.add_argument(
        "--yes",
        "--non-interactive",
        dest="non_interactive",
        action="store_true",
        help="Non-interactive: never prompt (e.g. for cert deletion when db full). Skip and exit with message instead.",
    )
    parser.add_argument(
        "--debug-secure-boot",
        action="store_true",
        help="GET and print SecureBoot and BIOS state from iLO (for troubleshooting disable). Use with one iLO IP and -p.",
    )
    parser.add_argument(
        "--bios-settings-file",
        metavar="FILE",
        default=None,
        help="Apply BIOS from a text file (key=value per line; optional # Model=, # CPU=, # CPU_Model= header).",
    )
    parser.add_argument(
        "--fetch-bios-settings",
        metavar="FILE",
        default=None,
        help="Fetch current BIOS and model/CPU from target(s). Write to FILE unless --no-write (then print to screen). No apply.",
    )
    parser.add_argument(
        "--no-write",
        action="store_true",
        help="With --fetch-bios-settings: do not write to file; print BIOS export to screen (e.g. when no write permission).",
    )
    parser.add_argument(
        "--no-bios",
        action="store_true",
        help="Do not apply any BIOS profile (only Secure Boot, cert, reboot if requested).",
    )
    _profile_choices = _list_profile_names()
    parser.add_argument(
        "--bios-profile",
        choices=_profile_choices if _profile_choices else None,
        default=None,
        metavar="NAME",
        help="Use named profile from bios_profiles/ (e.g. Nutanix_DL360G11_Intel). Default: auto-detect by model.",
    )
    parser.add_argument(
        "--match-model-cpu",
        action="store_true",
        help="When using --bios-settings-file: only apply if server model and CPU match the file header.",
    )
    parser.add_argument(
        "--output-format",
        choices=("text", "json"),
        default="text",
        help="Output format for --check and --fetch-bios-settings (and run summary when multi-target). Default: text.",
    )
    parser.add_argument("--bios-diff", action="store_true", help="With --check: only print attributes that differ from desired.")
    parser.add_argument("--list-profiles", action="store_true", help="List available BIOS profile names from bios_profiles/ and exit.")
    parser.add_argument(
        "--validate-profile",
        metavar="FILE",
        default=None,
        help="Validate a BIOS settings file (key=value format) and exit. No connection to iLO.",
    )
    parser.add_argument("--retries", type=int, default=MAX_ILO_RETRIES, metavar="N", help=f"Max API retries per iLO before skipping (default: {MAX_ILO_RETRIES}).")
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        metavar="N",
        help="Parallel workers for multiple iLOs (default: 1). When >1, reboot is skipped; use --reboot after run if needed.",
    )
    args = parser.parse_args()

    # Password from stdin: -p - (read one line)
    if getattr(args, "password", None) == "-":
        try:
            args.password = sys.stdin.readline().rstrip("\n\r")
        except (EOFError, OSError):
            args.password = ""

    # Configure logging (optional): --log-file writes to file; --verbose sets DEBUG
    if getattr(args, "log_file", None):
        level = logging.DEBUG if getattr(args, "verbose", False) else logging.INFO
        logger.setLevel(level)
        logger.handlers.clear()
        fh = logging.FileHandler(args.log_file, mode="a", encoding="utf-8")
        fh.setLevel(level)
        fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
        logger.addHandler(fh)
    else:
        logger.addHandler(logging.NullHandler())

    # Per-IP passwords and usernames (from -f file when used; else empty, use -p and -u)
    args.password_map = {}
    args.username_map = {}

    # --list-profiles: print profile names and exit
    if getattr(args, "list_profiles", False):
        for name in _list_profile_names():
            print(name)
        return 0

    # --validate-profile: validate file and exit
    if getattr(args, "validate_profile", None):
        ok, errs = _validate_bios_settings_file(args.validate_profile)
        if ok:
            print("OK: File is valid.")
            return 0
        for e in errs:
            print(e, file=sys.stderr)
        return 2

    # --dry-run: show what would be applied; no targets or password required
    if args.dry_run:
        if args.bios_settings_file:
            try:
                attrs, meta = _load_bios_settings_file(args.bios_settings_file)
                print(f"Dry run – BIOS from file: {args.bios_settings_file}")
                if meta:
                    print("  Metadata:", meta)
                for k, v in sorted(attrs.items()):
                    print(f"  {k}: {v}")
            except FileNotFoundError:
                print(f"Error: File not found: {args.bios_settings_file}", file=sys.stderr)
                return 2
            except OSError as e:
                print(f"Error reading {args.bios_settings_file}: {e}", file=sys.stderr)
                return 2
        elif args.bios_profile:
            attrs, _ = _load_profile_by_name(args.bios_profile)
            if attrs:
                print(f"Dry run – named profile: {args.bios_profile}")
                for k, v in sorted(attrs.items()):
                    print(f"  {k}: {v}")
            else:
                print(f"Dry run – profile {args.bios_profile} not found in {BIOS_PROFILES_DIR}", file=sys.stderr)
                return 2
        elif args.no_bios:
            print("Dry run – no BIOS profile (--no-bios); Secure Boot/cert/reboot only if requested.")
        else:
            print(f"Dry run – default profile by CPU ({DEFAULT_INTEL_PROFILE} / {DEFAULT_AMD_PROFILE}).")
            for label, name in [("Intel", DEFAULT_INTEL_PROFILE), ("AMD", DEFAULT_AMD_PROFILE)]:
                attrs, _ = _load_profile_by_name(name)
                if attrs:
                    print(f"\n{label} profile ({name}):")
                    for k, v in sorted(attrs.items()):
                        print(f"  {k}: {v}")
                else:
                    print(f"\n{label} profile {name}: (file not found)", file=sys.stderr)
        if args.enable_secure_boot:
            print("\nSecure Boot (with --enable-secure-boot):")
            for k, v in SECURE_BOOT_ATTRIBUTES.items():
                print(f"  {k}: {v}")
        if args.disable_secure_boot:
            print("\nSecure Boot: disabled (--disable-secure-boot)")
        return 0

    # Resolve target list: -f/--file or positional IPs. Same file can include optional username and password per line; missing -> use -u and -p.
    if args.file:
        try:
            targets, file_passwords, file_usernames = _load_ips_passwords_usernames(args.file)
            args.password_map = file_passwords
            args.username_map = file_usernames
        except FileNotFoundError:
            print(f"Error: File not found: {args.file}", file=sys.stderr)
            return 2
        except OSError as e:
            print(f"Error reading {args.file}: {e}", file=sys.stderr)
            return 2
        if not targets:
            print("Error: No IPs found in file.", file=sys.stderr)
            return 2
    elif args.ilo_ip:
        targets = list(args.ilo_ip)
    else:
        print("Error: Provide at least one iLO IP (ilo_ip [ilo_ip ...]) or use -f/--file.", file=sys.stderr)
        return 2

    # Deduplicate so each node is processed once (retries only on failure, not for duplicate entries)
    seen = set()
    unique_targets = []
    for t in targets:
        if t not in seen:
            seen.add(t)
            unique_targets.append(t)
    targets = unique_targets

    multi = len(targets) > 1
    if multi:
        print(f"Targets: {len(targets)} iLO(s)")
    # With multiple hosts: no interactive reboot prompt; --reboot reboots all
    prompt_reboot = not args.no_reboot_prompt and not multi
    yes_reboot = args.reboot
    if getattr(args, "skip_reboot", False):
        prompt_reboot = False
        yes_reboot = False

    # --cert-db-export: export Secure Boot db cert list to JSON file
    if getattr(args, "cert_db_export", None):
        if not args.password and not args.password_map:
            print("Error: Password required for --cert-db-export. Set ILO_PASSWORD, use -p, or set in -f file.", file=sys.stderr)
            return 2
        targets_data: List[Dict[str, Any]] = []
        for i, ip in enumerate(targets, 1):
            pwd = args.password_map.get(ip, args.password)
            if not pwd:
                if multi:
                    print(f"[{i}/{len(targets)}] {ip}: No password; skipping.", file=sys.stderr)
                continue
            if multi:
                print(f"[{i}/{len(targets)}] {ip} ...", file=sys.stderr)
            user = args.username_map.get(ip, args.user)
            if not probe_ilo_alive(ip, user, pwd, timeout=args.probe_timeout, verify_ssl=not args.no_verify_ssl):
                continue
            client = None
            try:
                kwargs = {"base_url": f"https://{ip}", "username": user, "password": pwd, "timeout": args.timeout}
                if args.no_verify_ssl:
                    kwargs["default_verify_cert"] = False
                try:
                    client = RedfishClient(**kwargs)
                except TypeError:
                    kwargs.pop("default_verify_cert", None)
                    client = RedfishClient(**kwargs)
                client.login()
                entries = _list_secure_boot_db_certificates(client)
                targets_data.append({"ilo_ip": ip, "certificates": [{"name": e.get("name") or "", "uri": e.get("uri") or "", "fingerprint": e.get("fingerprint")} for e in entries]})
            except Exception as e:
                print(f"  {ip}: {e}", file=sys.stderr)
            finally:
                if client is not None:
                    try:
                        client.logout()
                    except Exception:
                        pass
        if not targets_data:
            print("Error: Could not export cert db from any target.", file=sys.stderr)
            return 1
        try:
            with open(args.cert_db_export, "w", encoding=FILE_ENCODING) as f:
                if len(targets_data) == 1:
                    json.dump(targets_data[0], f, indent=2)
                else:
                    json.dump({"targets": targets_data}, f, indent=2)
            print(f"Exported Secure Boot db to {args.cert_db_export}")
        except OSError as e:
            print(f"Error writing {args.cert_db_export}: {e}", file=sys.stderr)
            return 2
        return 0

    # Fetch BIOS from first responsive node and exit (no apply)
    if args.fetch_bios_settings:
        if not args.password and not args.password_map:
            print("Error: Password required for --fetch-bios-settings. Set ILO_PASSWORD, use -p, or set password in -f file.", file=sys.stderr)
            return 2
        no_write = getattr(args, "no_write", False)
        for i, ip in enumerate(targets, 1):
            pwd = args.password_map.get(ip, args.password)
            if not pwd:
                if multi:
                    print(f"[{i}/{len(targets)}] {ip}: No password; set in -f file or use -p.", file=sys.stderr)
                continue
            if multi:
                print(f"[{i}/{len(targets)}] Trying {ip} ...", file=sys.stderr)
            user = args.username_map.get(ip, args.user)
            if not probe_ilo_alive(ip, user, pwd, timeout=args.probe_timeout, verify_ssl=not args.no_verify_ssl):
                continue
            ok, msg = fetch_bios_settings(
                ip, user, pwd, args.fetch_bios_settings,
                timeout=args.timeout, verify_ssl=not args.no_verify_ssl,
                no_write=no_write,
                output_format=getattr(args, "output_format", "text"),
            )
            if ok:
                print(msg)
                return 0
            print(f"  {ip}: {msg}", file=sys.stderr)
        print("Error: Could not fetch BIOS from any target.", file=sys.stderr)
        return 1

    if args.reset_bios_to_default:
        if not args.password and not args.password_map:
            print("Error: Password required for --reset-bios-to-default. Set ILO_PASSWORD, use -p, or set in -f file.", file=sys.stderr)
            return 2
        print("Note: For nodes in a Nutanix cluster with running workloads, use rolling_restart -h on the CVM to restart nodes safely.")
        any_fail = 0
        for i, ip in enumerate(targets, 1):
            pwd = args.password_map.get(ip, args.password)
            if not pwd:
                print(f"No password for {ip}; set in -f file or use -p/ILO_PASSWORD.", file=sys.stderr)
                any_fail = 1
                continue
            if multi:
                print(f"\n{'='*60}\n[{i}/{len(targets)}] {ip}\n{'='*60}")
            user = args.username_map.get(ip, args.user)
            if not probe_ilo_alive(ip, user, pwd, timeout=args.probe_timeout, verify_ssl=not args.no_verify_ssl):
                print(f"iLO at {ip} not responding, skipping.", file=sys.stderr)
                any_fail = 1
                continue
            client = None
            try:
                kwargs = {"base_url": f"https://{ip}", "username": user, "password": pwd, "timeout": args.timeout}
                if not args.no_verify_ssl:
                    pass
                else:
                    kwargs["default_verify_cert"] = False
                try:
                    client = RedfishClient(**kwargs)
                except TypeError:
                    kwargs.pop("default_verify_cert", None)
                    client = RedfishClient(**kwargs)
                client.login()
                if _reset_bios_to_default(client):
                    if args.reboot:
                        _do_reset(client)
                else:
                    any_fail = 1
            except Exception as e:
                print(f"Error: {e}", file=sys.stderr)
                any_fail = 1
            finally:
                if client is not None:
                    try:
                        client.logout()
                    except Exception:
                        pass
        return any_fail

    if args.debug_secure_boot:
        ip = targets[0]
        pwd = args.password_map.get(ip, args.password)
        if not pwd:
            print("Error: Password required for --debug-secure-boot. Set ILO_PASSWORD or use -p, or set in -f file.", file=sys.stderr)
            return 2
        user = args.username_map.get(ip, args.user)
        if not probe_ilo_alive(ip, user, pwd, timeout=args.probe_timeout, verify_ssl=not args.no_verify_ssl):
            print(f"iLO at {ip} not responding.", file=sys.stderr)
            return 1
        kwargs = {"base_url": f"https://{ip}", "username": user, "password": pwd, "timeout": args.timeout}
        if not args.no_verify_ssl:
            pass
        else:
            kwargs["default_verify_cert"] = False
        try:
            client = RedfishClient(**kwargs)
        except TypeError:
            kwargs.pop("default_verify_cert", None)
            client = RedfishClient(**kwargs)
        try:
            client.login()
            print(f"--- Debug Secure Boot for {ip} ---")
            _debug_secure_boot(client)
        finally:
            try:
                client.logout()
            except Exception:
                pass
        return 0

    if args.check:
        if not args.password and not args.password_map:
            print("Error: iLO password required for --check. Set ILO_PASSWORD, use -p, or set in -f file.", file=sys.stderr)
            return 2
        check_cert_pem: Optional[str] = None
        if args.secure_boot_cert:
            try:
                check_cert_pem = _load_cert_pem(args.secure_boot_cert)
            except FileNotFoundError:
                print(f"Error: Certificate file not found: {args.secure_boot_cert}", file=sys.stderr)
                return 2
            except Exception as e:
                print(f"Error loading certificate: {e}", file=sys.stderr)
                return 2
        check_base: Optional[Dict[str, str]] = None
        if args.bios_settings_file:
            try:
                check_attrs, _ = _load_bios_settings_file(args.bios_settings_file)
                check_base = check_attrs
            except Exception:
                pass
        any_fail = 0
        for i, ip in enumerate(targets, 1):
            pwd = args.password_map.get(ip, args.password)
            if not pwd:
                print(f"No password for {ip}; set in -f file or use -p/ILO_PASSWORD.", file=sys.stderr)
                any_fail = 1
                continue
            if multi:
                print(f"\n{'='*60}\n[{i}/{len(targets)}] {ip}\n{'='*60}")
            user = args.username_map.get(ip, args.user)
            if not probe_ilo_alive(ip, user, pwd, timeout=args.probe_timeout, verify_ssl=not args.no_verify_ssl):
                print(f"iLO at {ip} not responding (timeout/unreachable), skipping.", file=sys.stderr)
                any_fail = 1
                continue
            extra = None
            if args.enable_secure_boot:
                extra = SECURE_BOOT_ATTRIBUTES
            elif args.disable_secure_boot:
                extra = {"SecureBootEnable": False, **SECURE_BOOT_DISABLED_ATTRIBUTES}
            code = check_bios(
                ip,
                user,
                pwd,
                timeout=args.timeout,
                verify_ssl=not args.no_verify_ssl,
                extra_desired=extra,
                cert_pem=check_cert_pem,
                base_desired=check_base,
                profile_name=args.bios_profile or args.bios_settings_file,
                bios_diff=getattr(args, "bios_diff", False),
                output_format=getattr(args, "output_format", "text"),
            )
            if code != 0:
                any_fail = 1
        return any_fail

    if not args.password and not args.password_map:
        print("Error: iLO password required. Set ILO_PASSWORD, use -p, or set password per target in -f file.", file=sys.stderr)
        return 2

    desired_from_file: Optional[Dict[str, str]] = None
    file_metadata: Optional[Dict[str, str]] = None
    if args.bios_settings_file:
        try:
            attrs, meta = _load_bios_settings_file(args.bios_settings_file)
            desired_from_file = attrs
            file_metadata = meta if meta else None
            if not attrs:
                print(f"Warning: No attributes in {args.bios_settings_file}; only overrides will be applied.", file=sys.stderr)
        except FileNotFoundError:
            print(f"Error: BIOS settings file not found: {args.bios_settings_file}", file=sys.stderr)
            return 2
        except OSError as e:
            print(f"Error reading {args.bios_settings_file}: {e}", file=sys.stderr)
            return 2
    elif args.bios_profile:
        attrs, meta = _load_profile_by_name(args.bios_profile)
        if not attrs:
            print(f"Error: Profile '{args.bios_profile}' not found in {BIOS_PROFILES_DIR}.", file=sys.stderr)
            return 2
        desired_from_file = attrs
        file_metadata = meta
    elif args.no_bios:
        desired_from_file = {}

    overrides = {}
    if args.enable_secure_boot:
        overrides.update(SECURE_BOOT_ATTRIBUTES)
    if args.disable_secure_boot:
        overrides.update(SECURE_BOOT_DISABLED_ATTRIBUTES)
    always_apply_keys: Optional[Set[str]] = None
    if args.enable_secure_boot:
        always_apply_keys = set(SECURE_BOOT_ATTRIBUTES.keys())
    elif args.disable_secure_boot:
        always_apply_keys = set(SECURE_BOOT_DISABLED_ATTRIBUTES.keys())

    cert_pem: Optional[str] = None
    if args.secure_boot_cert:
        try:
            cert_pem = _load_cert_pem(args.secure_boot_cert)
        except FileNotFoundError:
            print(f"Error: Certificate file not found: {args.secure_boot_cert}", file=sys.stderr)
            return 2
        except Exception as e:
            print(f"Error loading certificate: {e}", file=sys.stderr)
            return 2

    max_retries = max(1, getattr(args, "retries", MAX_ILO_RETRIES))
    cert_verify_initial_delay_sec = getattr(args, "cert_verify_initial_delay", None)
    cert_verify_retry_delay_sec = getattr(args, "cert_verify_retry_delay", None)
    cert_verify_retries_opt = getattr(args, "cert_verify_retries", None)
    skip_reboot_run = prompt_reboot is False and yes_reboot is False
    if getattr(args, "workers", 1) > 1:
        skip_reboot_run = True  # never reboot when using parallel workers
    non_interactive = getattr(args, "non_interactive", False)
    workers = max(1, getattr(args, "workers", 1))

    success_list: List[str] = []
    failed_list: List[str] = []
    skipped_list: List[str] = []

    def _process_one(ip: str) -> Tuple[str, int]:
        """Process one iLO; returns (ip, exit_code)."""
        pwd = args.password_map.get(ip, args.password)
        if not pwd:
            return (ip, -1)  # -1 = skipped (no password)
        user = args.username_map.get(ip, args.user)
        if not probe_ilo_alive(ip, user, pwd, timeout=args.probe_timeout, verify_ssl=not args.no_verify_ssl):
            return (ip, -1)  # skipped (unreachable)
        code = 1
        for attempt in range(max_retries):
            code, _ = set_bios(
                ip,
                user,
                pwd,
                timeout=args.timeout,
                verify_ssl=not args.no_verify_ssl,
                prompt_reboot=prompt_reboot,
                yes_reboot=yes_reboot,
                skip_reboot=skip_reboot_run,
                non_interactive=non_interactive,
                attribute_overrides=overrides if overrides else None,
                always_apply_keys=always_apply_keys,
                cert_pem=cert_pem,
                enable_secure_boot_resource=args.enable_secure_boot,
                disable_secure_boot_resource=args.disable_secure_boot,
                desired_from_file=desired_from_file,
                file_metadata=file_metadata,
                match_model_cpu=args.match_model_cpu,
                profile_name=args.bios_profile or args.bios_settings_file,
                cert_verify_initial_delay_sec=cert_verify_initial_delay_sec,
                cert_verify_retry_delay_sec=cert_verify_retry_delay_sec,
                cert_verify_retries=cert_verify_retries_opt,
            )
            if code == 0:
                break
            if cert_pem:
                break
            if attempt + 1 < max_retries:
                print(f"  Retry {attempt + 2}/{max_retries} for {ip} ...", file=sys.stderr)
        return (ip, code)

    if workers > 1:
        # Parallel: submit all, collect results (output may interleave).
        # Timeout so one stuck host does not hang the run: allow (timeout * retries + buffer) per target.
        parallel_timeout = (args.timeout * max_retries + 120) * max(1, len(targets))
        if multi:
            print(f"Using {workers} parallel workers (reboot skipped).")
        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_ip = {executor.submit(_process_one, ip): ip for ip in targets}
            try:
                done_futures = set()
                for future in as_completed(future_to_ip.keys(), timeout=parallel_timeout):
                    done_futures.add(future)
                    ip = future_to_ip[future]
                    try:
                        _, code = future.result()
                    except Exception as e:
                        print(f"  {ip}: {e}", file=sys.stderr)
                        logger.exception("Parallel worker failed for %s", ip)
                        failed_list.append(ip)
                        continue
                    if code == -1:
                        skipped_list.append(ip)
                    elif code == 0:
                        success_list.append(ip)
                    else:
                        failed_list.append(ip)
            except TimeoutError:
                for future, ip in future_to_ip.items():
                    if future not in done_futures:
                        print(f"  {ip}: timed out (parallel run exceeded {parallel_timeout}s)", file=sys.stderr)
                        failed_list.append(ip)
                        future.cancel()
    else:
        # Sequential
        for i, ip in enumerate(targets, 1):
            pwd = args.password_map.get(ip, args.password)
            if not pwd:
                print(f"No password for {ip}; set in -f file or use -p/ILO_PASSWORD.", file=sys.stderr)
                skipped_list.append(ip)
                continue
            if multi:
                print(f"\n{'='*60}\n[{i}/{len(targets)}] {ip}\n{'='*60}")
            user = args.username_map.get(ip, args.user)
            if not probe_ilo_alive(ip, user, pwd, timeout=args.probe_timeout, verify_ssl=not args.no_verify_ssl):
                print(f"iLO at {ip} not responding (timeout/unreachable), skipping.", file=sys.stderr)
                skipped_list.append(ip)
                continue
            logger.info("Processing target %s (%s/%s)", ip, i, len(targets))
            code = 1
            for attempt in range(max_retries):
                code, _ = set_bios(
                    ip,
                    user,
                    pwd,
                    timeout=args.timeout,
                    verify_ssl=not args.no_verify_ssl,
                    prompt_reboot=prompt_reboot,
                    yes_reboot=yes_reboot,
                    skip_reboot=skip_reboot_run,
                    non_interactive=non_interactive,
                    attribute_overrides=overrides if overrides else None,
                    always_apply_keys=always_apply_keys,
                    cert_pem=cert_pem,
                    enable_secure_boot_resource=args.enable_secure_boot,
                    disable_secure_boot_resource=args.disable_secure_boot,
                    desired_from_file=desired_from_file,
                    file_metadata=file_metadata,
                    match_model_cpu=args.match_model_cpu,
                    profile_name=args.bios_profile or args.bios_settings_file,
                    cert_verify_initial_delay_sec=cert_verify_initial_delay_sec,
                    cert_verify_retry_delay_sec=cert_verify_retry_delay_sec,
                    cert_verify_retries=cert_verify_retries_opt,
                )
                if code == 0:
                    success_list.append(ip)
                    break
                if cert_pem:
                    failed_list.append(ip)
                    break
                if attempt + 1 < max_retries:
                    print(f"  Retry {attempt + 2}/{max_retries} for {ip} ...", file=sys.stderr)
            if code != 0 and ip not in success_list and ip not in failed_list:
                print(f"Skipping {ip} after {max_retries} failed attempt(s).", file=sys.stderr)
                failed_list.append(ip)

    any_fail = 1 if failed_list or skipped_list else 0
    if multi and (success_list or failed_list or skipped_list):
        out_fmt = getattr(args, "output_format", "text")
        if out_fmt == "json":
            print(json.dumps({"success": success_list, "failed": failed_list, "skipped": skipped_list}, indent=2))
        else:
            print(f"\n--- Summary ---")
            print(f"Success: {len(success_list)}  Failed: {len(failed_list)}  Skipped: {len(skipped_list)}")
            if failed_list:
                print(f"Failed: {', '.join(failed_list)}")
            if skipped_list:
                print(f"Skipped: {', '.join(skipped_list)}")
    return any_fail


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted by user (Ctrl+C).", file=sys.stderr)
        sys.exit(130)
