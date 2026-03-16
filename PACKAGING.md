# Packaging HPE Set BIOS

Step-by-step instructions to build and distribute the `hpe-set-bios` package.

## Prerequisites

- Python 3.6 or later
- Git (if cloning the repo)

## Step 1: Get the source

```bash
# If you have the repo locally:
cd /path/to/Auditsupportscripts

# Or clone (replace with your repo URL):
# git clone https://github.com/your-org/Auditsupportscripts.git
# cd Auditsupportscripts
```

## Step 2: Install build dependency (one-time)

To build a wheel and source distribution you need the `build` package:

```bash
python3 -m pip install build
```

## Step 3: Build the package

From the **repository root** (where `pyproject.toml` lives):

```bash
python3 -m build
```

This creates:

- `dist/hpe_set_bios-1.0.0-py3-none-any.whl` — installable wheel (use this for distribution)
- `dist/hpe_set_bios-1.0.0.tar.gz` — source archive

## Step 4: Install from the wheel (on this or another machine)

```bash
python3 -m pip install dist/hpe_set_bios-1.0.0-py3-none-any.whl
```

Then run:

```bash
hpe-set-bios --version
hpe-set-bios -f ips.txt -p 'password' --check
```

## Step 5: Distribute the wheel

- Copy `dist/hpe_set_bios-1.0.0-py3-none-any.whl` to the target machine (or share via internal artifact store).
- On the target machine: `pip install hpe_set_bios-1.0.0-py3-none-any.whl`
- Ensure `python-ilorest-library` is installed: `pip install python-ilorest-library` (the wheel lists it as a dependency, so `pip install` of the wheel usually installs it too).

## Optional: Install in editable mode (development)

To work on the code and run without rebuilding:

```bash
python3 -m pip install -e .
```

Then `hpe-set-bios` and `python3 HPE_set_bios.py` (from repo root) both use the current source.

## Optional: Bump version before building

Edit version in **two** places:

1. `pyproject.toml` — `version = "1.0.0"` (set to e.g. `"1.1.0"`)
2. `hpe_set_bios/__init__.py` — `__version__ = "1.0.0"`
3. `hpe_set_bios/cli.py` — `__version__ = "1.0.0"`

Then run `python3 -m build` again; the new version will appear in the filenames under `dist/`.

## Troubleshooting

| Issue | What to do |
|-------|------------|
| `command not found: hpe-set-bios` | Ensure the directory where pip installs scripts is on your PATH (e.g. `~/.local/bin` or `Library/Python/3.x/bin`). Run `python3 -m hpe_set_bios --version` instead, or use `python3 HPE_set_bios.py` from the repo. |
| `No module named 'redfish'` | Install dependency: `pip install python-ilorest-library` |
| urllib3 / OpenSSL warning | The script suppresses the common “urllib3 v2 only supports OpenSSL…” warning on LibreSSL systems. If you still see it, run via the package or the repo launcher (HPE_set_bios.py). |
| `bios_profiles` not found after install | Reinstall the wheel; package data should be included. If you run from repo without installing, keep the repo’s `bios_profiles/` directory next to `HPE_set_bios.py`. |

## Summary

| Goal | Command |
|------|--------|
| Build wheel + sdist | `python3 -m build` (from repo root) |
| Install from wheel | `pip install dist/hpe_set_bios-1.0.0-py3-none-any.whl` |
| Run after install | `hpe-set-bios` or `python3 -m hpe_set_bios` |
| Run from repo (no install) | `python3 HPE_set_bios.py` (after `pip install -r requirements.txt`) |
