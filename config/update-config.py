#!/usr/bin/env python2

"""
Take an options dictionary and update /etc/veil/settings.py
"""

import platform, os, sys, pwd

def generateConfig(options):

    # General
    config = """#!/usr/bin/python

##################################################################################################
#
# Veil configuration file
#
# Run 'Veil.py --config' to automatically set all these options to their defaults.
#
##################################################################################################


#################################################
#
# General system options
#
#################################################
"""
    print "\n Veil Configuration:"

    # OS
    config += '# OS to use (Kali/Backtrack/Debian/Windows)\n'
    config += 'OPERATING_SYSTEM="' + options['OPERATING_SYSTEM'] + '"\n\n'
    print " [*] OPERATING_SYSTEM = " + options['OPERATING_SYSTEM']

    # OS (Linux)
    config += '# Specific Linux distro\n'
    # Check /etc/issue for the exact linux distro
    issue = open("/etc/issue").read()
    if issue.startswith("Debian"):
        config += 'DISTRO="Debian"\n\n'
    else:
        config += 'DISTRO="Linux"\n\n'

    # Terminal clearing
    config += '# Terminal clearing method to use (use "false" to disable it)\n'
    config += 'TERMINAL_CLEAR="' + options['TERMINAL_CLEAR'] + '"\n\n'
    print " [*] TERMINAL_CLEAR = " + options['TERMINAL_CLEAR']

    # Wine
    config += '# Wine environment\n'
    config += 'WINEPREFIX="' + options["WINEPREFIX"] + '"\n\n'
    print " [*] WINEPREFIX = " + options["WINEPREFIX"]

    # Temp folder
    config += '# Path to temporary directory\n'
    config += 'TEMP_DIR="' + options["TEMP_DIR"] + '"\n\n'
    print " [*] TEMP_DIR = " + options["TEMP_DIR"]

    # Metasploit-Framework
    config += '# The path to the metasploit framework, for example: /usr/share/metasploit-framework/\n'
    config += 'METASPLOIT_PATH="' + options['METASPLOIT_PATH'] + '"\n\n'
    print " [*] METASPLOIT_PATH = " + options['METASPLOIT_PATH']

    # msfvenom
    config += '# The path to msfvenom for shellcode generation purposes\n'
    config += 'MSFVENOM_PATH="' + options["MSFVENOM_PATH"] + '"\n\n'
    print " [*] MSFVENOM_PATH = " + options["MSFVENOM_PATH"]

    # msfvenom
    config += '# Default options to pass to msfvenom for shellcode creation\n'
    config += 'MSFVENOM_OPTIONS="' + options['MSFVENOM_OPTIONS'] + '"\n\n'
    print " [*] MSFVENOM_OPTIONS = " + options['MSFVENOM_OPTIONS']

    # PyInstaller Path
    config += '# The path to pyinstaller, for example: /opt/pyinstaller-2.0/\n'
    config += 'PYINSTALLER_PATH="' + options['PYINSTALLER_PATH'] + '"\n\n'
    print " [*] PYINSTALLER_PATH = " + options['PYINSTALLER_PATH'] + "\n"


    # Veil-Evasion
    config += """

#################################################
#
# Veil-Evasion specific options
#
#################################################
"""
    print "\n Veil-Evasion Configuration:"

    # Veil-Evasion path
    config += '# Veil-Evasion install path\n'
    config += 'VEIL_EVASION_PATH="' + options['VEIL_EVASION_PATH'] + '"\n\n'
    print " [*] VEIL_EVASION_PATH = " + options['VEIL_EVASION_PATH']

    # Payload path
    source_path = os.path.expanduser( options["PAYLOAD_SOURCE_PATH"] )
    config += '# Path to output the source of payloads\n'
    config += 'PAYLOAD_SOURCE_PATH="' + source_path + '"\n\n'
    print " [*] PAYLOAD_SOURCE_PATH = " + source_path

    # Compile path
    compiled_path = os.path.expanduser( options["PAYLOAD_COMPILED_PATH"] )
    config += '# Path to output compiled payloads\n'
    config += 'PAYLOAD_COMPILED_PATH="' + compiled_path +'"\n\n'
    print " [*] PAYLOAD_COMPILED_PATH = " + compiled_path

    # Handler path
    handler_path = os.path.expanduser( options["HANDLER_PATH"] )
    config += '# Whether to generate a msf handler script and where to place it\n'
    config += 'GENERATE_HANDLER_SCRIPT="' + options['GENERATE_HANDLER_SCRIPT'] + '"\n'
    print " [*] GENERATE_HANDLER_SCRIPT = " + options['GENERATE_HANDLER_SCRIPT']
    config += 'HANDLER_PATH="' + handler_path + '"\n\n'
    print " [*] HANDLER_PATH = " + handler_path

    # Hash List
    hash_path = os.path.expanduser( options["HASH_LIST"] )
    config += '# Running hash list of all payloads generated\n'
    config += 'HASH_LIST="' + hash_path + '"\n\n'
    print " [*] HASH_LIST = " + hash_path + "\n"


    # Veil-Catapult
    config += """

#################################################
#
# Veil-Catapult specific options
#
#################################################
"""
    print "\n Veil-Catapult Configuration:"

    # Veil-Catapult path
    config += '# Veil-Catapult install path\n'
    config += 'VEIL_CATAPULT_PATH="' + options['VEIL_CATAPULT_PATH'] + '"\n\n'
    print " [*] VEIL_CATAPULT_PATH = " + options['VEIL_CATAPULT_PATH']

    # Veil-Catapult resource path
    catapult_resource_path = os.path.expanduser( options["CATAPULT_RESOURCE_PATH"] )
    config += '# Path to output Veil-Catapult resource/cleanup files\n'
    config += 'CATAPULT_RESOURCE_PATH="' + catapult_resource_path + '"\n\n'
    print " [*] CATAPULT_RESOURCE_PATH = " + catapult_resource_path + "\n"


    # Create the output compiled path if it doesn't exist
    if not os.path.exists( handler_path ):
        os.makedirs( handler_path )
        print " [I] Path Created: '" + handler_path

    # Create the catapult resource path if it doesn't exist
    if not os.path.exists( catapult_resource_path ):
        os.makedirs( catapult_resource_path )
        print " [I] Path Created: '" + catapult_resource_path

    # Create the output source path if it doesn't exist
    if not os.path.exists( source_path ):
        os.makedirs( source_path )
        print " [I] Path Created: '" + source_path

    # Create the output compiled path if it doesn't exist
    if not os.path.exists( compiled_path ):
        os.makedirs( compiled_path )
        print " [I] Path Created: '" + compiled_path


    # Save config
    if platform.system() == "Linux":
        # create the output compiled path if it doesn't exist
        if not os.path.exists( "/etc/veil/" ):
            os.makedirs( "/etc/veil/" )
            print " [I] Path '/etc/veil/' Created"
        f = open( "/etc/veil/settings.py", 'w' )
        f.write( config )
        f.close()
        os.chmod( "/etc/veil/settings.py", 0755 )
        print " [I] Configuration File Written To: '/etc/veil/settings.py'\n"
    else:
        print " [!] ERROR: PLATFORM NOT CURRENTLY SUPPORTED"
        sys.exit()


if __name__ == '__main__':

    options = {}

    # Check for root access
    if os.geteuid() != 0:
        print " [!] ERROR: Not root. Requesting..."
        os.execvp( "sudo", ["sudo"] + ["python"] + sys.argv )
        sys.exit()

    if platform.system() == "Linux":

        # Check /etc/issue for the exact linux distro
        issue = open( "/etc/issue" ).read()

        # General options
        options["METASPLOIT_PATH"] = "/opt/metasploit-framework/"
        options["MSFVENOM_OPTIONS"] = ""
        options["MSFVENOM_PATH"] = "/usr/local/bin/"
        options["OPERATING_SYSTEM"] = "Linux"
        options["PYINSTALLER_PATH"] = "/var/lib/veil/PyInstaller-3.2.1/"
        options["TEMP_DIR"] = "/tmp/"
        options["TERMINAL_CLEAR"] = "clear"
        options["WINEPREFIX"] = "/var/lib/veil/wine/veil/"

        # Veil-Evasion specific options
        veil_evasion_path = "/".join( os.getcwd().split( "/" )[:-1] ) + "/"
        options["VEIL_EVASION_PATH"] = veil_evasion_path
        options["GENERATE_HANDLER_SCRIPT"] = "True"
        options["HANDLER_PATH"] = "/var/lib/veil/output/handlers/"
        options["HASH_LIST"] = "/var/lib/veil/output/hashes.txt"
        options["PAYLOAD_COMPILED_PATH"] = "/var/lib/veil/output/compiled/"
        options["PAYLOAD_SOURCE_PATH"] = "/var/lib/veil/output/source/"

        # Veil-Catapult specific options
        veil_catapult_path = "/".join( os.getcwd().split( "/" )[:-2] ) + "/Veil-Catapult/"
        options["VEIL_CATAPULT_PATH"] = veil_catapult_path
        options["CATAPULT_RESOURCE_PATH"] = "/var/lib/veil/output/catapult/"

        # Kali
        if issue.startswith( "Kali" ):
            options["OPERATING_SYSTEM"] = "Kali"
            options["METASPLOIT_PATH"] = "/usr/share/metasploit-framework/"
            options["MSFVENOM_PATH"] = "/usr/bin/"
            options["TERMINAL_CLEAR"] = "false"
        # BackTrack
        elif issue.startswith( "BackTrack" ):
            options["OPERATING_SYSTEM"] = "BackTrack"
            options["METASPLOIT_PATH"] = "/opt/metasploit/msf3/"
            options["MSFVENOM_PATH"] = "/opt/metasploit/msf3/"

        # Check the paths are correct (METASPLOIT_PATH)
        while not os.path.isdir( options["METASPLOIT_PATH"] ):
            msfpath = raw_input( " [>] Please enter the directory of the Metasploit Framework (e.g. /opt/metasploit-framework/): " )
            options["METASPLOIT_PATH"] = msfpath

        # Check the paths are correct (MSFVENOM_PATH)
        while not os.path.isfile( options["MSFVENOM_PATH"] + "/msfvenom" ):
            msfpath = raw_input( " [>] Please enter the directory of msfvenom (e.g. /usr/bin/): " )
            options["MSFVENOM_PATH"] = msfpath

    # Unsupported platform...
    else:
        print " [!] ERROR: PLATFORM NOT CURRENTLY SUPPORTED"
        sys.exit()

    generateConfig( options )
