'''

This file is used for messages that will be displayed to the user at some
point

'''

import os
import sys
from lib.common import helpers

# try to find and import the settings.py config file
if os.path.exists("/etc/veil/settings.py"):
    try:
        sys.path.append("/etc/veil/")
        import settings
    except:
        print("Error importing Veil Settings!")
        sys.exit(1)

# Current version of Veil
veil_version = "3.1.4"


def title_screen():
    """
    Print the framework title, with version.
    """
    os.system('clear')
    print('=' * 79)
    print(' ' * 29 + helpers.color('Veil', status=False, bold=True) + ' | [Version]: ' + veil_version)
    print('=' * 79)
    print('      [Web]: https://www.veil-framework.com/ | [Twitter]: @VeilFramework')
    print('=' * 79 + '\n')
    return
