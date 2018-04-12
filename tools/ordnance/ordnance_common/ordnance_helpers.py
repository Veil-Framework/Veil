"""
This file contains random helper functions for Veil-Ordnance
"""

import os
import random
import re
import socket
import string
import struct
import sys
from lib.common import helpers

# Try to find and import the settings.py config file
try:
    sys.path.append("/etc/veil/")
    import settings
except ImportError:
    print( "\n [!] ERROR #1-9: Can't import /etc/veil/settings.py.   Run: %s\n" % ( os.path.abspath( "./config/update-config.py" ) ) )
    sys.exit()


def check_lhost(lhost_value):
    if validate_ip(lhost_value):
        return True
    else:
        try:
            lhost_value = socket.gethostbyname(lhost_value)
            return True
        except socket.gaierror:
            return False


def check_lport(lport_value):
    try:
        if int(lport_value):
            if 0 < int(lport_value) < 65535:
                return True
        else:
            return False
    except ValueError:
        return False


def checksum_eight(string_checked):
    current_sum = 0
    num_Bs = len(string_checked)
    letter_values = struct.unpack("B" * num_Bs, string_checked.encode('UTF-8'))
    for value in letter_values:
        current_sum += value
    return current_sum % 0x100


def gen_uri():
    goal_sum = 92
    all_characters = list(string.digits + string.ascii_letters)
    while True:
        uri = ''.join(random.choice(string.ascii_letters + string.digits) for x in range(3))
        for character in all_characters:
            full_uri = uri + character
            string_sum = checksum_eight(full_uri)
            if string_sum == goal_sum:
                return full_uri


def loop_req_options(payload_object):
    blank_options = False
    for required_option_name in payload_object.required_options.keys():
        if payload_object.required_options[required_option_name][0] == "":
            blank_options = True
    return blank_options


def title_screen():
    """
    Print the framework title, with version.
    """
    if settings.TERMINAL_CLEAR != "false":
      os.system('clear')

    print('=' * 79)
    print(' ' * 35 + helpers.color('Veil-Ordnance', status=False, bold=True))
    print('=' * 79)
    print('      [Web]: https://www.veil-framework.com/ | [Twitter]: @VeilFramework')
    print('=' * 79 + '\n')
    return


def validate_ip(val_ip):
    # This came from (Mult-line link for pep8 compliance)
    # http://python-iptools.googlecode.com/svn-history/r4
    # /trunk/iptools/__init__.py
    ip_re = re.compile(r'^(\d{1,3}\.){0,3}\d{1,3}$')
    if ip_re.match(val_ip):
        quads = (int(q) for q in val_ip.split('.'))
        for q in quads:
            if q > 255:
                return False
        return True
    return False
