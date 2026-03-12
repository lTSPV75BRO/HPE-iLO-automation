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
import os
import sys
import time
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

if sys.version_info < (3, 6):
    print("Error: This script requires Python 3.6 or later.", file=sys.stderr)
    sys.exit(2)

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

# Profiles live in bios_profiles/*.txt (no inline dicts). Names = filename without .txt.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BIOS_PROFILES_DIR = os.path.join(SCRIPT_DIR, "bios_profiles")
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


def _save_bios_settings_file(path: str, model: str, cpu_vendor: str, cpu_model: str, attributes: Dict[str, str]) -> None:
    """Write BIOS settings to a text file with metadata header (Model, CPU, CPU_Model)."""
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
    with open(path, "w", encoding=FILE_ENCODING) as f:
        f.write("\n".join(lines) + "\n")


def fetch_bios_settings(
    ilo_ip: str,
    username: str,
    password: str,
    output_path: str,
    timeout: int = DEFAULT_TIMEOUT,
    verify_ssl: bool = True,
) -> Tuple[bool, str]:
    """
    GET current BIOS Attributes and system model/CPU from iLO, write to a text file.
    Returns (success: bool, message: str). File format: # Model=... # CPU=... # CPU_Model=... then key=value per line.
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
    ips: List[str] = []
    try:
        with open(path, "r", encoding=FILE_ENCODING, errors="replace") as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                ips.append(line)
    except OSError:
        raise
    return ips


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


# Retries for Secure Boot cert upload (and short delay between retries)
SECURE_BOOT_CERT_RETRIES = 3
SECURE_BOOT_CERT_RETRY_DELAY_SEC = 2
# After 202 Accepted, iLO may need time to persist; wait before first verification
SECURE_BOOT_CERT_VERIFY_INITIAL_DELAY_SEC = 4
SECURE_BOOT_CERT_VERIFY_RETRIES = 5


def _pem_to_64_char_lines(pem: str) -> str:
    """Return PEM with base64 body wrapped to 64 chars per line (some iLOs require this)."""
    b64 = _normalize_cert_pem_for_compare(pem)
    if not b64:
        return pem.replace("\r\n", "\n").strip() + "\n"
    lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----\n"


def _import_secure_boot_cert(client: Any, cert_pem: str) -> bool:
    """POST certificate to Secure Boot Authorized Signature Database (db). Tries multiple URIs and payload formats. Returns True on success or if cert already in db. BIOS must be in User mode."""
    # Normalize: CRLF -> LF, 64-char lines for base64 (some iLOs require), trailing newline (per HPE doc)
    cert_string = _pem_to_64_char_lines(cert_pem)
    # Base64-only (no PEM headers) for variants that expect it
    b64_only = _normalize_cert_pem_for_compare(cert_pem)
    uris_to_try = [
        SECURE_BOOT_DB_CERTIFICATES_URI,
        "/redfish/v1/Systems/1/SecureBoot/SecureBootDatabases/db/Certificates",
        SECURE_BOOT_DB_CERTIFICATES_PAYLOAD_URI,
    ]
    # HPE doc: CertificateString + CertificateType "PEM" first; then other variants
    bodies_to_try = [
        {"CertificateString": cert_string, "CertificateType": "PEM"},
        {"Certificate": cert_string},
        {"CertificateString": cert_string, "CertificateType": "x509"},
        {"CertificateString": b64_only, "CertificateType": "Base64"},
    ]
    last_err = None
    for attempt in range(1, SECURE_BOOT_CERT_RETRIES + 1):
        try:
            for uri in uris_to_try:
                for body in bodies_to_try:
                    try:
                        resp = client.post(uri, body)
                    except Exception as e:
                        last_err = str(e)
                        continue
                    status = getattr(resp, "status", None)
                    resp_text = (getattr(resp, "text", None) or "")[:400]
                    if status in (200, 201, 202, 204):
                        print("Secure Boot certificate accepted by iLO (import to Authorized Signature Database).")
                        time.sleep(SECURE_BOOT_CERT_VERIFY_INITIAL_DELAY_SEC)
                        for v in range(SECURE_BOOT_CERT_VERIFY_RETRIES):
                            if _verify_cert_in_secure_boot_db(client, cert_pem):
                                print("Certificate verified: present in iLO Secure Boot db.")
                                return True
                            if v < SECURE_BOOT_CERT_VERIFY_RETRIES - 1:
                                time.sleep(SECURE_BOOT_CERT_RETRY_DELAY_SEC)
                        print("Certificate import reported success; re-check db in iLO if needed.", file=sys.stderr)
                        return True
                    if status and 400 <= status < 500:
                        time.sleep(1)
                        if _verify_cert_in_secure_boot_db(client, cert_pem):
                            print("Certificate already in db; verified present.")
                            return True
                        last_err = f"status {status} {resp_text}"
                        print(f"  Cert POST {uri}: {last_err}", file=sys.stderr)
                        continue
                    last_err = f"status {status} {resp_text}"
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
    attribute_overrides: Optional[Dict[str, str]] = None,
    always_apply_keys: Optional[Iterable[str]] = None,
    cert_pem: Optional[str] = None,
    enable_secure_boot_resource: bool = False,
    disable_secure_boot_resource: bool = False,
    desired_from_file: Optional[Dict[str, str]] = None,
    file_metadata: Optional[Dict[str, str]] = None,
    match_model_cpu: bool = False,
    profile_name: Optional[str] = None,
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
                _import_secure_boot_cert(client, cert_pem)
            if yes_reboot:
                _do_reset(client)
            elif prompt_reboot and sys.stdin.isatty():
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
            _import_secure_boot_cert(client, cert_pem)

        # 4. Confirm: read back pending Settings
        pending = _get_attributes(client, BIOS_SETTINGS_URI)
        print("Pending BIOS (Settings) – confirmation:")
        for key in desired:
            val = pending.get(key, "<not reported>")
            print(f"  {key}: {val}")
        print()

        # 5. Reboot prompt (or --reboot when multi: no prompt, but still reboot if requested)
        if prompt_reboot:
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
        elif yes_reboot:
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
) -> int:
    """
    Connect to iLO, detect CPU type, get current BIOS and desired profile,
    print comparison (current vs desired) and return 0 if all match, 1 if any differ.
    If base_desired is provided (e.g. from file), use it as the base; else use built-in by CPU.
    If cert_pem is provided, also checks whether that certificate is enrolled in Secure Boot db.
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

        print(f"{'Attribute':<35} {'Current':<28} {'Desired':<28} {'Match'}")
        print("-" * 95)

        all_match = True
        for key in sorted(desired.keys()):
            cur = current.get(key)
            cur_str = str(cur) if cur is not None else "<not set>"
            want = desired[key]
            # VMD port keys: if iLO does not report the attribute (port not present on platform), treat as N/A not DIFF
            if key.startswith("Vmdon") and cur is None:
                print(f"{key:<35} {cur_str[:27]:<28} {str(want)[:27]:<28} {'N/A'}")
                continue
            match = cur is not None and str(cur).strip() == str(want).strip()
            if not match:
                all_match = False
            status = "OK" if match else "DIFF"
            print(f"{key:<35} {cur_str[:27]:<28} {str(want)[:27]:<28} {status}")

        print()
        if all_match:
            print("All BIOS settings match the desired profile.")
        else:
            print("One or more BIOS settings differ from the desired profile.")

        # Check if certificate (file) is enrolled in Secure Boot db
        if cert_pem:
            enrolled = _verify_cert_in_secure_boot_db(client, cert_pem)
            print(f"Certificate (file) enrolled in Secure Boot db: {'Yes' if enrolled else 'No'}")
            if not enrolled:
                all_match = False

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
        description="Set HPE node BIOS via iLO Redfish (production-ready, idempotent). BIOS is optional: use built-in profile, --bios-settings-file, or --no-bios.",
        epilog="Use --fetch-bios-settings to export from a reference server; then --bios-settings-file + --match-model-cpu to apply to same model/CPU.",
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
        help=f"File with one iLO IP per line; -f alone uses {DEFAULT_INPUT_FILE}",
    )
    parser.add_argument("-u", "--user", "--username", dest="user", default=DEFAULT_USERNAME, metavar="USER", help=f"iLO username (default: {DEFAULT_USERNAME})")
    parser.add_argument("-p", "--password", default=DEFAULT_PASSWORD, help="iLO password (default: ILO_PASSWORD env)")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help=f"Timeout in seconds for API calls (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("--probe-timeout", type=int, default=PROBE_TIMEOUT, metavar="SEC", help=f"Timeout for iLO alive probe in seconds (default: {PROBE_TIMEOUT})")
    parser.add_argument("--no-verify-ssl", action="store_true", help="Disable SSL certificate verification")
    parser.add_argument("--check", action="store_true", help="Compare current BIOS to desired profile (no changes); exit 0 if match, 1 if differ")
    parser.add_argument("--dry-run", action="store_true", help="Only print desired attributes; do not connect or PATCH")
    parser.add_argument("--no-reboot-prompt", action="store_true", help="Do not ask to reboot server after applying settings")
    parser.add_argument("--reboot", action="store_true", help="Reboot server after applying settings (no prompt)")
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
        help="Fetch current BIOS and model/CPU from target(s), write to FILE (first successful node). No apply.",
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
    args = parser.parse_args()

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

    # Resolve target list: -f/--file or positional IPs
    if args.file:
        try:
            targets = _load_ips(args.file)
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

    # Fetch BIOS from first responsive node and exit (no apply)
    if args.fetch_bios_settings:
        if not args.password:
            print("Error: Password required for --fetch-bios-settings. Set ILO_PASSWORD or use -p.", file=sys.stderr)
            return 2
        for i, ip in enumerate(targets, 1):
            if multi:
                print(f"[{i}/{len(targets)}] Trying {ip} ...", file=sys.stderr)
            if not probe_ilo_alive(ip, args.user, args.password, timeout=args.probe_timeout, verify_ssl=not args.no_verify_ssl):
                continue
            ok, msg = fetch_bios_settings(
                ip, args.user, args.password, args.fetch_bios_settings,
                timeout=args.timeout, verify_ssl=not args.no_verify_ssl,
            )
            if ok:
                print(msg)
                return 0
            print(f"  {ip}: {msg}", file=sys.stderr)
        print("Error: Could not fetch BIOS from any target.", file=sys.stderr)
        return 1

    if args.reset_bios_to_default:
        if not args.password:
            print("Error: Password required for --reset-bios-to-default. Set ILO_PASSWORD or use -p.", file=sys.stderr)
            return 2
        print("Note: For nodes in a Nutanix cluster with running workloads, use rolling_restart -h on the CVM to restart nodes safely.")
        any_fail = 0
        for i, ip in enumerate(targets, 1):
            if multi:
                print(f"\n{'='*60}\n[{i}/{len(targets)}] {ip}\n{'='*60}")
            if not probe_ilo_alive(ip, args.user, args.password, timeout=args.probe_timeout, verify_ssl=not args.no_verify_ssl):
                print(f"iLO at {ip} not responding, skipping.", file=sys.stderr)
                any_fail = 1
                continue
            client = None
            try:
                kwargs = {"base_url": f"https://{ip}", "username": args.user, "password": args.password, "timeout": args.timeout}
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
        if not args.password:
            print("Error: Password required for --debug-secure-boot. Set ILO_PASSWORD or use -p.", file=sys.stderr)
            return 2
        ip = targets[0]
        if not probe_ilo_alive(ip, args.user, args.password, timeout=args.probe_timeout, verify_ssl=not args.no_verify_ssl):
            print(f"iLO at {ip} not responding.", file=sys.stderr)
            return 1
        kwargs = {"base_url": f"https://{ip}", "username": args.user, "password": args.password, "timeout": args.timeout}
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
        if not args.password:
            print("Error: iLO password required for --check. Set ILO_PASSWORD or use -p.", file=sys.stderr)
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
            if multi:
                print(f"\n{'='*60}\n[{i}/{len(targets)}] {ip}\n{'='*60}")
            if not probe_ilo_alive(ip, args.user, args.password, timeout=args.probe_timeout, verify_ssl=not args.no_verify_ssl):
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
                args.user,
                args.password,
                timeout=args.timeout,
                verify_ssl=not args.no_verify_ssl,
                extra_desired=extra,
                cert_pem=check_cert_pem,
                base_desired=check_base,
                profile_name=args.bios_profile or args.bios_settings_file,
            )
            if code != 0:
                any_fail = 1
        return any_fail

    if not args.password:
        print("Error: iLO password required. Set ILO_PASSWORD or use -p.", file=sys.stderr)
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

    any_fail = 0
    for i, ip in enumerate(targets, 1):
        if multi:
            print(f"\n{'='*60}\n[{i}/{len(targets)}] {ip}\n{'='*60}")
        if not probe_ilo_alive(ip, args.user, args.password, timeout=args.probe_timeout, verify_ssl=not args.no_verify_ssl):
            print(f"iLO at {ip} not responding (timeout/unreachable), skipping.", file=sys.stderr)
            any_fail = 1
            continue
        code = 1
        for attempt in range(MAX_ILO_RETRIES):
            code, _ = set_bios(
                ip,
                args.user,
                args.password,
                timeout=args.timeout,
                verify_ssl=not args.no_verify_ssl,
                prompt_reboot=prompt_reboot,
                yes_reboot=yes_reboot,
                attribute_overrides=overrides if overrides else None,
                always_apply_keys=always_apply_keys,
                cert_pem=cert_pem,
                enable_secure_boot_resource=args.enable_secure_boot,
                disable_secure_boot_resource=args.disable_secure_boot,
                desired_from_file=desired_from_file,
                file_metadata=file_metadata,
                match_model_cpu=args.match_model_cpu,
                profile_name=args.bios_profile or args.bios_settings_file,
            )
            if code == 0:
                break
            if attempt + 1 < MAX_ILO_RETRIES:
                print(f"  Retry {attempt + 2}/{MAX_ILO_RETRIES} for {ip} ...", file=sys.stderr)
        if code != 0:
            print(f"Skipping {ip} after {MAX_ILO_RETRIES} failed attempt(s).", file=sys.stderr)
            any_fail = 1
    return any_fail


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted by user (Ctrl+C).", file=sys.stderr)
        sys.exit(130)
