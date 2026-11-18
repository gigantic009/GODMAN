"""Application entry point."""
import sys
from pathlib import Path

# Make the src-layout package importable without installing it yet.
sys.path.insert(0, str(Path(__file__).parent / "src"))

from jarvis.cli import main

if __name__ == "__main__":
    main()
