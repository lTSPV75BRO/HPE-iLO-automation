# Contributing to HPE iLO automation scripts

Thank you for your interest in contributing. This document outlines how to report issues, suggest changes, and submit contributions.

## Code of conduct

- Be respectful and constructive in issues and pull requests.
- Focus on the code and the problem; avoid personal remarks.

## How to contribute

### Reporting bugs or asking for features

1. **Check existing issues** on GitHub to see if the topic is already reported.
2. **Open a new issue** with a clear title and description:
   - **Bug:** What you did, what you expected, what happened (include script version, Python version, and iLO/model if relevant).
   - **Feature:** Use case and why it would help; example usage if possible.

### Submitting changes (pull requests)

1. **Fork the repository** and create a branch from `main` (e.g. `feature/add-xyz` or `fix/issue-123`).
2. **Make your changes** and keep them focused (one logical change per PR when possible).
3. **Test** with at least one iLO if you changed BIOS or inventory logic.
4. **Commit** with a clear message (e.g. `Add --foo option to HPE_set_bios.py`).
5. **Push** your branch and open a **Pull Request** against `main`.
6. In the PR description, briefly say what changed and why; link any related issue.

### What we look for

- **Compatibility:** Python 3.6+; rely on `python-ilorest-library` for Redfish (no new heavy dependencies without good reason).
- **Style:** Match existing style (e.g. type hints where used, docstrings for public functions).
- **Safety:** Do not add code that logs or stores passwords; keep secrets in env or CLI only.
- **Docs:** Update README or script docstrings if you add or change user-facing options or behavior.

### Development setup

```bash
git clone https://github.com/lTSPV75BRO/HPE-iLO-automation.git
cd HPE-iLO-automation
pip install -r requirements.txt
# Use a test iLO and -f with a small ips.txt for testing
```

### Scope of the project

- **In scope:** HPE iLO Redfish automation (BIOS, inventory, Secure Boot, certificates), Nutanix-oriented profiles, robustness and documentation.
- **Out of scope:** General Redfish or non-HPE BMC tooling belongs in other repos; we can link to them from the README if useful.

If you have questions, open an issue and we can discuss.
