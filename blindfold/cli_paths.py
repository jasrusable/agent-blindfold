"""Paths of this checkout, shared by the CLI and the selftest."""

import os

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LAUNCHER = os.path.join(REPO, "bin", "blindfold")
SKILL_DIR = os.path.join(REPO, "skill", "blindfold")
