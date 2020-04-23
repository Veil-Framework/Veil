"""
This file is used for messages that will be displayed to the user at some point
"""

import os
import sys
from lib.common import helpers

# Try to find and import the settings.py config file
try:
    sys.path.append("/etc/veil/")
    import settings
except ImportError:
    print( "\n [!] ERROR #1-8: Can't import /etc/veil/settings.py.   Run: %s\n" % ( os.path.abspath( "./config/update-config.py" ) ) )
    sys.exit()

# Current version of Veil
veil_version = "3.1.14"


def title_screen():
    """
    Print the framework title, with version.
    """
    if settings.TERMINAL_CLEAR != "false":
        os.system('clear')

    print('=' * 79)
    print(' ' * 29 + helpers.color('Veil', status=False, bold=True) + ' | [Version]: ' + veil_version)
    print('=' * 79)
    print('      [Web]: https://www.veil-framework.com/ | [Twitter]: @VeilFramework')
    print('=' * 79 + '\n')
    return
