# Copy these lines into the WSGI configuration file on PythonAnywhere (Web tab > WSGI configuration file),
# after replacing YOUR_USERNAME with your PythonAnywhere username.
import sys

path = "/home/YOUR_USERNAME/raqib-site"
if path not in sys.path:
    sys.path.insert(0, path)

from app import app as application  # noqa: E402,F401
