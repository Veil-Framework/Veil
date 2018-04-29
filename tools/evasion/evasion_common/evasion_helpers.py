"""
"""

import base64
import os
import random
import string
import subprocess
import sys
import textwrap
import zlib
from lib.common import helpers


# Try to find and import the settings.py config file
try:
    sys.path.append("/etc/veil/")
    import settings
except ImportError:
    print( "\n [!] ERROR #1-6: Can't import /etc/veil/settings.py.   Run: %s\n" % ( os.path.abspath( "./config/update-config.py" ) ) )
    sys.exit()


def deflate(string_val):
    """
    Compress/base64 encode a string. Used in powershell invokers.
    """
    string_val = string_val.encode()
    zlibbed_str = zlib.compress(string_val)
    compressed_string = zlibbed_str[2:-4]
    return base64.b64encode(compressed_string).decode('ascii')


def compileToTemp(language, payloadSource):
    """
    Compiles payload code to a temporary location and returns the path.
    """
    if language == "cs":

        tempExeName = settings.TEMP_PATH + 'temp.exe'
        tempSourceName = settings.TEMP_PATH + 'temp.cs'

        # write out the payload source to the temporary location
        with open(settings.TEMP_PATH + 'temp.cs', 'w') as f:
            f.write(payloadSource)

        # Compile our CS code into an executable and pass a compiler flag to prevent it from opening a command prompt when run
        os.system('mcs -platform:x86 -target:winexe ' + tempSourceName + ' -out:' + tempExeName)
        return tempExeName


def expiring_payload_variables():
    # Expiring payload specific variables
    RandToday = randomString()
    RandExpire = randomString()
    return RandToday, RandExpire


def format_long(title, message, frontTab=True, spacing=16):
    """
    Print a long title:message with our standardized formatting.
    Wraps multiple lines into a nice paragraph format.
    """

    lines = textwrap.wrap(textwrap.dedent(message).strip(), width=50)
    returnString = ""

    i = 1
    if len(lines) > 0:
        if frontTab:
            returnString += "\t%s%s" % (('{0: <%s}' % spacing).format(title), lines[0])
        else:
            returnString += " %s%s" % (('{0: <%s}' % (spacing-1)).format(title), lines[0])
    while i < len(lines):
        if frontTab:
            returnString += "\n\t" + ' ' * spacing + lines[i]
        else:
            returnString += "\n" + ' ' * spacing + lines[i]
        i += 1
    return returnString


def inflate(b64string):
    """
    Decode/decompress a base64 string. Used in powershell invokers.
    """
    decoded_data = base64.b64decode(b64string)
    return zlib.decompress(decoded_data, -15).encode('ascii')


def LHOST():
    """
    Return the IP of eth0
    """
    ip_output = subprocess.getoutput("/sbin/ifconfig eth0").split("\n")[1].split()[1]
    if 'addr' in ip_output:
        ip_output = ip_output[5:]
    return ip_output


def obfuscateNum(N, mod):
    """
    Take a number and modulus and return an obfuscated form.
    Returns a string of the obfuscated number N
    """
    d = random.randint(1, mod)
    left = int(N / d)
    right = d
    remainder = N % d
    return "(%s*%s+%s)" % (left, right, remainder)


def print_dict_message(commands, show_title=True):
    if show_title:
        title_screen()

    print(helpers.color(" Available Commands:\n"))

    # list commands in sorted order
    for (cmd, desc) in sorted(commands.items()):
        print("\t%s\t%s" % ('{0: <12}'.format(cmd), desc))
    print()
    return


def randomString(length=-1):
    """
    Returns a random string of "length" characters.
    If no length is specified, resulting string is in
    between 6 and 15 characters.
    """
    if length == -1:
        length = random.randrange(6, 16)
    random_string = ''.join(random.choice(string.ascii_letters) for x in range(length))
    return random_string


def title_screen():
    """
    Print the framework title, with version.
    """
    if settings.TERMINAL_CLEAR != "false":
        os.system('clear')

    print('=' * 79)
    print(' ' * 35 + helpers.color('Veil-Evasion', status=False, bold=True))
    print('=' * 79)
    print('      [Web]: https://www.veil-framework.com/ | [Twitter]: @VeilFramework')
    print('=' * 79 + '\n')
    return
