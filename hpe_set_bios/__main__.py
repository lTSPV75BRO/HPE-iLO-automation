"""Allow running as python -m hpe_set_bios."""
from .cli import main
import sys

if __name__ == "__main__":
    sys.exit(main())
