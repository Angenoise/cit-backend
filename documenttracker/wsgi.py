"""Compatibility WSGI module for Render root-level startup commands."""

import os
import sys
from pathlib import Path

from django.core.wsgi import get_wsgi_application

# Ensure the inner project folder is importable when starting from repo root.
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
	sys.path.insert(0, str(BASE_DIR))

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "documenttracker.settings")

application = get_wsgi_application()
