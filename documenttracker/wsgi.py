"""Compatibility WSGI module for Render root-level startup commands."""

import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "documenttracker.documenttracker.settings")

application = get_wsgi_application()
