# documenttracker/wsgi.py
"""
WSGI config for documenttracker project.
"""
import os
from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'documenttracker.settings')
application = get_wsgi_application()
