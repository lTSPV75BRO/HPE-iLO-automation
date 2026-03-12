#!/usr/bin/env python3
"""
HPE iLO Redfish inventory collector (production-ready).

Reads iLO IPs from a file, queries each via Redfish for system/hardware details,
outputs CSV and/or JSON. Optional: export BIOS settings per model/CPU for use with HPE_set_bios.py.

Configuration:
  Environment variables (override CLI defaults):
    ILO_USER       - iLO username (default: Administrator)
    ILO_PASSWORD   - iLO password (required in production; no default)
    ILO_INPUT_FILE - Path to file with one IP per line (default: ips.txt)
    ILO_TIMEOUT    - Request timeout in seconds (default: 30)
  Use -u/--user and -p/--password for CLI; password from ILO_PASSWORD if -p not set.

  --fetch-bios-settings DIR: Export current BIOS + model/CPU to DIR (one file per model+CPU).
  Use those files with HPE_set_bios.py --bios-settings-file and --match-model-cpu to apply
  the same BIOS to other servers with the same model and CPU.

  --strict: Exit with failure if any node fails (default: exit 1 when any fail).

Nutanix Foundation: The main CSV/JSON includes Node_Position, IP (BMC), Server_Name (Hostname), Serial, UUID, Model, CPU_Model, etc.

Requires Python 3.6+ (3.8+ recommended). Dependencies: pip install -r requirements.txt
"""
import argparse
import csv
import io
import json
import logging
import os
import re
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

if sys.version_info < (3, 6):
    print("Error: This script requires Python 3.6 or later.", file=sys.stderr)
    print(f"Current: {sys.executable} -> {sys.version}", file=sys.stderr)
    sys.exit(2)

SCRIPT_VERSION = "2.0"

# Handle --version and --create-requirements before importing redfish/tabulate
if "--version" in sys.argv:
    print(f"HPEilodetials.py version {SCRIPT_VERSION}", file=sys.stderr)
    print(f"Python: {sys.executable}", file=sys.stderr)
    print(f"Python version: {sys.version}", file=sys.stderr)
    sys.exit(0)

# Default encoding for file I/O
FILE_ENCODING = "utf-8"

_REQUIREMENTS_TXT = """# HPE iLO Redfish inventory (HPEilodetials.py)
# Python 3.6+ required; 3.8+ recommended for python-ilorest-library.

# HPE Redfish client (provides RedfishClient for iLO).
# If you see "cannot import name 'RedfishClient' from 'redfish'", uninstall
# the generic redfish package and reinstall: pip uninstall redfish
# then: pip install -r requirements.txt
python-ilorest-library>=3.0.0

# Table output
tabulate>=0.9.0
"""

if "--create-requirements" in sys.argv:
    out_path = "requirements.txt"
    # Allow: --create-requirements other.txt
    try:
        i = sys.argv.index("--create-requirements")
        if i + 1 < len(sys.argv) and not sys.argv[i + 1].startswith("-"):
            out_path = sys.argv[i + 1]
    except ValueError:
        pass
    try:
        with open(out_path, "w") as f:
            f.write(_REQUIREMENTS_TXT)
        print(f"Wrote {out_path}", file=sys.stderr)
    except OSError as e:
        print(f"Error writing {out_path}: {e}", file=sys.stderr)
        sys.exit(1)
    sys.exit(0)

# HPE python-ilorest-library provides RedfishClient. If you see "(unknown location)" or
# ImportError, a broken "redfish" folder was left after uninstalling the DMTF redfish
# package. Fix: remove that folder and reinstall the HPE library (see error message below).
try:
    from redfish import RedfishClient
except ImportError:
    try:
        from redfish.rest.v1 import RedfishClient
    except ImportError:
        _site = next(
            (p for p in sys.path if "site-packages" in p and "Python" in p),
            "site-packages",
        )
        print(
            "Error: RedfishClient not found. The 'redfish' package is broken (often after\n"
            "  'pip uninstall redfish'). Fix it with one of these:\n\n"
            "  1) Clean reinstall (recommended):\n"
            "     pip3 uninstall python-ilorest-library redfish -y\n"
            "     pip3 install python-ilorest-library tabulate\n\n"
            "  2) If that fails, remove the broken redfish folder and reinstall:\n"
            f"     rm -rf \"{_site}/redfish\"\n"
            "     pip3 install --force-reinstall python-ilorest-library tabulate\n",
            file=sys.stderr,
        )
        sys.exit(1)

# --- Config: env vars first, then CLI ---
DEFAULT_INPUT_FILE = os.environ.get("ILO_INPUT_FILE", "ips.txt")
DEFAULT_USERNAME = os.environ.get("ILO_USER", "Administrator")
DEFAULT_PASSWORD = os.environ.get("ILO_PASSWORD", "")  # No default in production; require env or -p
DEFAULT_TIMEOUT = int(os.environ.get("ILO_TIMEOUT", "30"))

# Exit codes
EXIT_SUCCESS = 0
EXIT_PARTIAL_OR_FAIL = 1
EXIT_USAGE = 2

# Single merged output: Node_Position + inventory; firmwares and disks in separate columns (no duplicates)
FIELD_NAMES = [
    "Node_Position",
    "IP",
    "Server_Name",
    "Model",
    "Serial",
    "CPU_Model",
    "CPU_Config",
    "RAM_GB",
    "Disk_Count",
    "Total_Disks",
    "Disk_SSD_Count",
    "Disk_HDD_Count",
    "Disk_NVMe_Count",
    "Disk_Summary",
    "Disk_Model",
    "Power_State",
    "Manufacturer",
    "UUID",
    "iLO_Firmware",
    "BIOS_Version",
    "Firmware_Storage",
    "Firmware_Drive",
    "Firmware_NIC",
    "Firmware_Other",
    "NIC_Count",
    "NIC_Summary",
]

# Simple IPv4 pattern for validation (allow hostname later if needed)
IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def _setup_logging(level: str) -> logging.Logger:
    """Configure stderr logging; return logger."""
    log_level = getattr(logging, level.upper(), logging.INFO)
    fmt = "%(asctime)s %(levelname)s %(message)s"
    logging.basicConfig(level=log_level, format=fmt, stream=sys.stderr, datefmt="%Y-%m-%d %H:%M:%S")
    return logging.getLogger(__name__)


def _validate_ip(addr: str) -> bool:
    """Return True if addr looks like an IPv4 address."""
    if not IPV4_RE.match(addr):
        return False
    return all(0 <= int(octet) <= 255 for octet in addr.split("."))


def _sanitize_bios_filename(s: str) -> str:
    """Replace characters unsuitable for filenames with underscore."""
    if not s or not isinstance(s, str):
        return "Unknown"
    return re.sub(r"[\s/\\]+", "_", s).strip("_") or "Unknown"


def _write_bios_settings_file(
    output_dir: str,
    model: str,
    cpu_vendor: str,
    cpu_model: str,
    attributes: Dict[str, Any],
    log: Optional[logging.Logger] = None,
) -> Optional[str]:
    """Write BIOS attributes to output_dir/bios_<model>_<cpu>.txt (same format as HPE_set_bios --bios-settings-file). Returns path written or None."""
    logger = log or logging.getLogger(__name__)
    try:
        os.makedirs(output_dir, exist_ok=True)
        safe_model = _sanitize_bios_filename(model)[:50]
        safe_cpu = _sanitize_bios_filename(cpu_vendor)[:20]
        path = os.path.join(output_dir, f"bios_{safe_model}_{safe_cpu}.txt")
        lines = [
            "# BIOS settings export from iLO Redfish (use with HPE_set_bios.py --bios-settings-file)",
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
        logger.info("Wrote BIOS profile: %s (%d attributes)", path, len(attributes))
        return path
    except OSError as e:
        logger.warning("Could not write BIOS file: %s", e)
        return None


def get_node_data(
    ilo_ip: str,
    username: str,
    password: str,
    timeout: int,
    verify_ssl: bool = True,
    log: Optional[logging.Logger] = None,
    retries: int = 1,
    export_bios_dir: Optional[str] = None,
) -> Tuple[Dict[str, Any], Optional[str]]:
    """Query a single iLO via Redfish and return (node_dict, error_message or None)."""
    logger = log or logging.getLogger(__name__)
    node: Dict[str, Any] = {
        "IP": ilo_ip,
        "Server_Name": "N/A",
        "Model": "N/A",
        "Serial": "N/A",
        "CPU_Model": "N/A",
        "CPU_Config": "N/A",
        "RAM_GB": 0,
        "Disk_Count": 0,
        "Total_Disks": 0,
        "Disk_SSD_Count": 0,
        "Disk_HDD_Count": 0,
        "Disk_NVMe_Count": 0,
        "Disk_Summary": "N/A",
        "Disk_Model": "N/A",
        "Power_State": "N/A",
        "Manufacturer": "N/A",
        "UUID": "N/A",
        "iLO_Firmware": "N/A",
        "BIOS_Version": "N/A",
        "Firmware_Storage": "N/A",
        "Firmware_Drive": "N/A",
        "Firmware_NIC": "N/A",
        "Firmware_Other": "N/A",
        "NIC_Count": 0,
        "NIC_Summary": "N/A",
    }
    client = None
    last_err: Optional[Exception] = None
    for attempt in range(max(1, retries)):
        if attempt > 0 and logger.isEnabledFor(logging.DEBUG):
            logger.debug("Retry %s/%s for %s", attempt + 1, retries, ilo_ip)
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

            # 1. System info & name fallback
            sys_resp = client.get("/redfish/v1/Systems/1/")
            sys = sys_resp.dict

            name = sys.get("HostName")
            if not name or name == "Computer System":
                mgr_net = client.get("/redfish/v1/Managers/1/NetworkProtocol/").dict
                name = mgr_net.get("HostName")

            # 2. CPU: query individual processors for accurate core count
            proc_col_uri = sys.get("Processors", {}).get("@odata.id")
            proc_col = client.get(proc_col_uri).dict

            cpu_model = "N/A"
            sockets = 0
            cores_per_socket = 0

            for member in proc_col.get("Members", []):
                proc = client.get(member["@odata.id"]).dict
                if proc.get("ProcessorType") == "CPU":
                    sockets += 1
                    cpu_model = proc.get("Model", cpu_model)
                    cores_per_socket = proc.get("TotalCores") or proc.get("Cores", 0)

            ram_gib = sys.get("MemorySummary", {}).get("TotalSystemMemoryGiB")
            if ram_gib is None:
                ram_gib = 0

            node.update({
                "Server_Name": name or "Unknown",
                "Model": sys.get("Model"),
                "Serial": sys.get("SerialNumber"),
                "CPU_Model": cpu_model,
                "CPU_Config": f"{cores_per_socket} x {sockets}" if sockets > 0 else "N/A",
                "RAM_GB": ram_gib,
                "Power_State": sys.get("PowerState"),
                "Manufacturer": sys.get("Manufacturer"),
                "UUID": sys.get("UUID"),
            })

            # 3. iLO (Manager) firmware version
            try:
                mgr = client.get("/redfish/v1/Managers/1/").dict
                node["iLO_Firmware"] = mgr.get("FirmwareVersion") or "N/A"
            except Exception:
                pass

            # 4. BIOS version and optional export of full BIOS settings
            bios_attrs: Dict[str, Any] = {}
            try:
                bios = client.get("/redfish/v1/Systems/1/Bios/").dict
                node["BIOS_Version"] = (
                    bios.get("Version")
                    or bios.get("AttributeRegistry")
                    or (bios.get("Oem", {}).get("Hpe", {}) or {}).get("CurrentBIOSVersion")
                    or "N/A"
                )
                bios_attrs = bios.get("Attributes") or {}
            except Exception:
                pass

            if export_bios_dir and bios_attrs and node.get("Model") and node.get("CPU_Model"):
                cpu_vendor = "AMD" if "AMD" in str(node.get("CPU_Model", "")).upper() else "Intel"
                _write_bios_settings_file(
                    export_bios_dir,
                    node["Model"],
                    cpu_vendor,
                    node["CPU_Model"],
                    bios_attrs,
                    log=logger,
                )

            # 4b. Firmware inventory – separate columns, deduplicated by component
            fw_storage: List[str] = []
            fw_drive: List[str] = []
            fw_nic: List[str] = []
            fw_other: List[str] = []
            fw_seen: set = set()  # (name, ver) tuples to avoid duplicate firmware entries

            def _add_fw(category: str, name: str, ver: str) -> None:
                key = (name, ver)
                if key in fw_seen:
                    return
                fw_seen.add(key)
                entry = f"{name}: {ver}"
                name_lower = name.lower()
                if "storage" in name_lower or "controller" in name_lower or "array" in name_lower:
                    fw_storage.append(entry)
                elif "drive" in name_lower or "ssd" in name_lower or "disk" in name_lower:
                    fw_drive.append(entry)
                elif "nic" in name_lower or "network" in name_lower or "ethernet" in name_lower:
                    fw_nic.append(entry)
                elif "ilo" in name_lower or "bmc" in name_lower or "bios" in name_lower:
                    pass  # already in iLO_Firmware / BIOS_Version
                else:
                    fw_other.append(entry)

            for fw_inv_uri in (
                "/redfish/v1/UpdateService/FirmwareInventory",
                "/redfish/v1/Managers/1/UpdateService/FirmwareInventory",
            ):
                try:
                    fw_inv = client.get(fw_inv_uri).dict
                    for member in fw_inv.get("Members", []):
                        try:
                            item = client.get(member["@odata.id"]).dict
                            name = item.get("Name") or item.get("Id") or "Unknown"
                            ver = item.get("Version") or item.get("SoftwareId") or "N/A"
                            _add_fw("", name, ver)
                        except Exception:
                            continue
                    break
                except Exception:
                    continue

            # 5. Disk aggregation + storage/drive firmware from Storage API (no duplicates)
            storage = client.get("/redfish/v1/Systems/1/Storage/").dict
            disk_map: Dict[str, int] = {}
            disk_models: List[str] = []  # drive Model for Disk_Model summary
            total_count = 0
            ssd_count = 0
            hdd_count = 0
            nvme_count = 0

            for member in storage.get("Members", []):
                ctrl_uri = member.get("@odata.id")
                ctrl = client.get(ctrl_uri).dict
                ctrl_fw = ctrl.get("FirmwareVersion")
                if ctrl_fw:
                    ctrl_name = ctrl.get("Name") or ctrl.get("Id") or "Storage"
                    _add_fw("storage", ctrl_name, ctrl_fw)
                for drive_ref in ctrl.get("Drives", []):
                    d = client.get(drive_ref["@odata.id"]).dict
                    cap_gb = round(d.get("CapacityBytes", 0) / (1024**3), 1)
                    media = (d.get("MediaType") or "Unknown").upper()
                    protocol = (d.get("Protocol") or "").upper()
                    spec = f"{cap_gb}GB {d.get('MediaType', 'Unknown')}"
                    disk_map[spec] = disk_map.get(spec, 0) + 1
                    total_count += 1
                    if "NVME" in protocol or "NVME" in media:
                        nvme_count += 1
                    elif "SSD" in media or "SOLID" in media:
                        ssd_count += 1
                    else:
                        hdd_count += 1
                    disk_models.append(d.get("Model") or d.get("Manufacturer") or "Unknown")
                    drive_fw = d.get("FirmwareVersion")
                    if drive_fw:
                        _add_fw("drive", "Drive", drive_fw)

            if fw_storage:
                node["Firmware_Storage"] = " | ".join(fw_storage)
            if fw_drive:
                node["Firmware_Drive"] = " | ".join(fw_drive)
            if fw_nic:
                node["Firmware_NIC"] = " | ".join(fw_nic)
            if fw_other:
                node["Firmware_Other"] = " | ".join(fw_other)

            node["Disk_Count"] = total_count
            node["Total_Disks"] = total_count
            node["Disk_SSD_Count"] = ssd_count
            node["Disk_HDD_Count"] = hdd_count
            node["Disk_NVMe_Count"] = nvme_count
            node["Disk_Summary"] = " | ".join([f"{count}x {s}" for s, count in sorted(disk_map.items())]) if disk_map else "N/A"
            if disk_models:
                node["Disk_Model"] = " | ".join([f"{c}x {m}" for m, c in Counter(disk_models).most_common()])

            # 6. Network adapters (NIC count and summary)
            try:
                nic_models = []
                for chassis_id in ("1", "0"):
                    try:
                        na_col = client.get(f"/redfish/v1/Chassis/{chassis_id}/NetworkAdapters/").dict
                        for na_member in na_col.get("Members", []):
                            try:
                                na = client.get(na_member["@odata.id"]).dict
                                model = na.get("Model") or na.get("Manufacturer") or "NIC"
                                nic_models.append(model)
                            except Exception:
                                nic_models.append("NIC")
                        if nic_models:
                            break
                    except Exception:
                        continue
                if nic_models:
                    counts = Counter(nic_models)
                    node["NIC_Count"] = len(nic_models)
                    node["NIC_Summary"] = " | ".join([f"{c}x {m}" for m, c in counts.most_common()])
            except Exception:
                pass

            for key in ("Power_State", "Manufacturer", "UUID"):
                if node.get(key) is None:
                    node[key] = "N/A"

            return node, None
        except Exception as e:
            last_err = e
            logger.debug("Attempt failed for %s: %s", ilo_ip, e)
            continue
        finally:
            if client is not None:
                try:
                    client.logout()
                except Exception:
                    pass

    err_msg = str(last_err).split("\n")[0] if last_err and str(last_err) else (type(last_err).__name__ if last_err else "Unknown")
    node["Server_Name"] = f"ERROR: {err_msg}"
    return node, err_msg


def load_ips(path: str, validate: bool = True) -> List[str]:
    """Load IPs from file (one per line); skip empty lines and # comments. Optionally validate IPv4."""
    ips: List[str] = []
    with open(path, "r", encoding=FILE_ENCODING) as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            if validate and not _validate_ip(line):
                logging.getLogger(__name__).warning("Skipping invalid IP/hostname: %s", line)
                continue
            ips.append(line)
    return ips


def _results_with_node_position(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Return copy of results with Node_Position (1-based) added for merged Foundation/main output."""
    return [{"Node_Position": i, **r} for i, r in enumerate(results, 1)]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Collect HPE iLO hardware inventory via Redfish. Output CSV or JSON.",
        epilog="Production: set ILO_PASSWORD in the environment; avoid -p with secrets in process list.",
    )
    parser.add_argument(
        "-i", "--input",
        default=DEFAULT_INPUT_FILE,
        help=f"Input file with one iLO IP per line (default: {DEFAULT_INPUT_FILE})",
    )
    parser.add_argument(
        "-o", "--output-csv",
        metavar="FILE",
        help="Write inventory CSV/JSON to FILE (includes Node_Position and all fields for Foundation use)",
    )
    parser.add_argument(
        "-u", "--user",
        default=DEFAULT_USERNAME,
        help=f"iLO username (default: {DEFAULT_USERNAME})",
    )
    parser.add_argument(
        "-p", "--password",
        default=DEFAULT_PASSWORD,
        help="iLO password (default: ILO_PASSWORD env; unset in production)",
    )
    parser.add_argument(
        "-t", "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"Request timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "--no-verify-ssl",
        action="store_true",
        help="Disable SSL certificate verification (use only in lab/dev)",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress progress and table; only print CSV",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Print per-IP errors to stderr and show Python interpreter in use",
    )
    parser.add_argument(
        "--version",
        action="store_true",
        help="Show script version and which Python interpreter is running this script",
    )
    parser.add_argument("--retries", type=int, default=1, metavar="N",
                        help="Retry each host up to N times (default: 1)")
    parser.add_argument("--workers", "-w", type=int, default=2, metavar="N",
                        help="Parallel workers for querying hosts (default: 2)")
    parser.add_argument("--log-level", default="WARNING", choices=("DEBUG", "INFO", "WARNING", "ERROR"),
                        help="Logging level (default: WARNING)")
    parser.add_argument("--format", choices=("csv", "json"), default="csv",
                        help="Stdout format (default: csv)")
    parser.add_argument("--no-validate-ips", action="store_true",
                        help="Allow hostnames in input; do not validate IPv4")
    parser.add_argument(
        "--create-requirements",
        nargs="?",
        metavar="FILE",
        const="requirements.txt",
        help="Write requirements.txt (or FILE) and exit; use before installing deps",
    )
    parser.add_argument(
        "--fetch-bios-settings",
        metavar="DIR",
        default=None,
        help="Export current BIOS settings + model/CPU to DIR (one file per model+CPU; use with HPE_set_bios.py --bios-settings-file)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit with failure if any node fails (default: exit 0 when at least one succeeds)",
    )
    args = parser.parse_args()

    log = _setup_logging(args.log_level)
    if args.verbose:
        log.info("Python: %s", sys.executable)
        log.info("Python version: %s", sys.version.split()[0])

    if not args.password:
        log.warning("No iLO password set (use ILO_PASSWORD or -p). Connections may fail.")

    try:
        ips = load_ips(args.input, validate=not args.no_validate_ips)
    except FileNotFoundError:
        log.error("Input file not found: %s", args.input)
        sys.exit(EXIT_USAGE)
    except OSError as e:
        log.error("Error reading %s: %s", args.input, e)
        sys.exit(EXIT_USAGE)

    if not ips:
        log.warning("No IPs found in input file.")
        sys.exit(EXIT_SUCCESS)

    # Deduplicate IPs while preserving order (avoids duplicate rows in CSV)
    seen_ips: set = set()
    unique_ips: List[str] = []
    for ip in ips:
        if ip not in seen_ips:
            seen_ips.add(ip)
            unique_ips.append(ip)
    if len(unique_ips) < len(ips):
        log.info("Dropped %s duplicate IP(s); %s unique hosts", len(ips) - len(unique_ips), len(unique_ips))
    ips = unique_ips

    results: List[Dict[str, Any]] = []
    failed: List[Tuple[str, str]] = []
    workers = max(1, args.workers)

    def _fetch_one(ip: str) -> Tuple[Dict[str, Any], Optional[str]]:
        return get_node_data(
            ip,
            username=args.user,
            password=args.password,
            timeout=args.timeout,
            verify_ssl=not args.no_verify_ssl,
            log=log,
            retries=args.retries,
            export_bios_dir=args.fetch_bios_settings,
        )

    if workers == 1:
        for i, ip in enumerate(ips, 1):
            if not args.quiet:
                print(f"Processing {i}/{len(ips)}: {ip} ...", file=sys.stderr)
            node, err = _fetch_one(ip)
            results.append(node)
            if err:
                failed.append((ip, err))
                log.warning("Failed %s: %s", ip, err)
    else:
        if not args.quiet:
            print(f"Processing {len(ips)} hosts with {workers} workers ...", file=sys.stderr)
        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_ip = {executor.submit(_fetch_one, ip): ip for ip in ips}
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    node, err = future.result()
                    results.append((ip, node, err))
                except Exception as e:
                    log.warning("Worker error for %s: %s", ip, e)
                    results.append((ip, {"IP": ip, "Server_Name": f"ERROR: {e}"}, str(e)))
        # Restore order by IP list so Node_Position matches input order
        ip_to_result = {r[0]: (r[1], r[2]) for r in results}
        results = []
        for ip in ips:
            node, err = ip_to_result[ip]
            results.append(node)
            if err:
                failed.append((ip, err))

    output_rows = _results_with_node_position(results)

    # Stdout: CSV or JSON (merged: Node_Position + all inventory; usable for Foundation)
    if args.format == "json":
        print(json.dumps(output_rows, indent=2))
    else:
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=FIELD_NAMES, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(output_rows)
        csv_text = buf.getvalue()
        print(csv_text)

    # Optional: write merged inventory to file (same columns as stdout; Foundation-ready)
    if args.output_csv:
        try:
            if args.format == "csv":
                buf = io.StringIO()
                csv.DictWriter(buf, fieldnames=FIELD_NAMES, extrasaction="ignore").writeheader()
                csv.DictWriter(buf, fieldnames=FIELD_NAMES, extrasaction="ignore").writerows(output_rows)
                with open(args.output_csv, "w", newline="", encoding=FILE_ENCODING) as f:
                    f.write(buf.getvalue())
            else:
                with open(args.output_csv, "w", encoding=FILE_ENCODING) as f:
                    json.dump(output_rows, f, indent=2)
            log.info("Wrote %s", args.output_csv)
        except OSError as e:
            log.error("Error writing %s: %s", args.output_csv, e)

    if failed:
        print(f"\nFailed: {len(failed)}/{len(ips)}", file=sys.stderr)
        for ip, err in failed:
            print(f"  {ip}: {err}", file=sys.stderr)
        sys.exit(EXIT_PARTIAL_OR_FAIL)
    if not args.quiet and results:
        log.info("Success: %s/%s hosts", len(results), len(ips))


if __name__ == "__main__":
    main()
