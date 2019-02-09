#!/usr/bin/env python3

"""
Take an options dictionary and update /etc/veil/settings.py

Able to call this by doing: Veil.py --config
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
    print( "\n Veil Configuration:" )

    # OS
    config += '# OS to use (Kali/Backtrack/Debian/Windows)\n'
    config += 'OPERATING_SYSTEM="' + options['OPERATING_SYSTEM'] + '"\n\n'
    print( " [*] OPERATING_SYSTEM = " + options['OPERATING_SYSTEM'] )

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
    print( " [*] TERMINAL_CLEAR = " + options['TERMINAL_CLEAR'] )

    # Veil's path
    config += '# Veil install path\n'
    config += 'VEIL_PATH="' + options['VEIL_PATH'] + '"\n\n'
    print( " [*] VEIL_PATH = " + options['VEIL_PATH'] )

    # Wine's path
    config += '# Wine environment\n'
    config += 'WINEPREFIX="' + options["WINEPREFIX"] + '"\n\n'
    print( " [*] WINEPREFIX = " + options["WINEPREFIX"] )

    # Temp path
    config += '# Path to temporary directory\n'
    config += 'TEMP_PATH="' + options["TEMP_PATH"] + '"\n\n'
    print( " [*] TEMP_PATH = " + options["TEMP_PATH"] )

    # Metasploit Framework's path
    config += '# The path to the metasploit framework, for example: %s\n' % ( options['METASPLOIT_PATH'] )
    config += 'METASPLOIT_PATH="' + options['METASPLOIT_PATH'] + '"\n\n'
    print( " [*] METASPLOIT_PATH = " + options['METASPLOIT_PATH'] )

    # msfvenom's path
    config += '# The path to msfvenom for shellcode generation purposes\n'
    config += 'MSFVENOM_PATH="' + options["MSFVENOM_PATH"] + '"\n\n'
    print( " [*] MSFVENOM_PATH = " + options["MSFVENOM_PATH"] )

    # msfvenom's options
    config += '# Default options to pass to msfvenom for shellcode creation\n'
    config += 'MSFVENOM_OPTIONS="' + options['MSFVENOM_OPTIONS'] + '"\n\n'
    print( " [*] MSFVENOM_OPTIONS = " + options['MSFVENOM_OPTIONS'] )

    # PyInstaller's path
    config += '# The path to pyinstaller, for example: %s\n' % ( options['PYINSTALLER_PATH'] )
    config += 'PYINSTALLER_PATH="' + options['PYINSTALLER_PATH'] + '"\n\n'
    print( " [*] PYINSTALLER_PATH = " + options['PYINSTALLER_PATH'] )

    # GoLang's path
    config += '# The path to pyinstaller, for example: %s\n' % ( options['GOLANG_PATH'] )
    config += 'GOLANG_PATH="' + options['GOLANG_PATH'] + '"\n\n'
    print( " [*] GOLANG_PATH = " + options['GOLANG_PATH'])

    # Padding between sections
    print ( "\n" )

    # Veil-Evasion
    config += """

#################################################
#
# Veil-Evasion specific options
#
#################################################
"""
    print( "\n Veil-Evasion Configuration:" )

    # Payload path
    source_path = os.path.expanduser( options["PAYLOAD_SOURCE_PATH"] )
    config += '# Path to output the source of payloads\n'
    config += 'PAYLOAD_SOURCE_PATH="' + source_path + '"\n\n'
    print( " [*] PAYLOAD_SOURCE_PATH = " + source_path )

    # Compile path
    compiled_path = os.path.expanduser( options["PAYLOAD_COMPILED_PATH"] )
    config += '# Path to output compiled payloads\n'
    config += 'PAYLOAD_COMPILED_PATH="' + compiled_path +'"\n\n'
    print( " [*] PAYLOAD_COMPILED_PATH = " + compiled_path )

    # Handler path
    handler_path = os.path.expanduser( options["HANDLER_PATH"] )
    config += '# Where to generate a msf handler script\n'
    config += 'HANDLER_PATH="' + handler_path + '"\n\n'
    print( " [*] HANDLER_PATH = " + handler_path )

    # Hash List file
    hash_path = os.path.expanduser( options["HASH_LIST"] )
    config += '# Running hash list of all payloads generated\n'
    config += 'HASH_LIST="' + hash_path + '"\n\n'
    print( " [*] HASH_LIST = " + hash_path )

    # Create the output compiled path if it doesn't exist
    if not os.path.exists( handler_path ):
        os.makedirs( handler_path )
        print( " [I] Path Created: '" + handler_path )

    # Create the output source path if it doesn't exist
    if not os.path.exists( source_path ):
        os.makedirs( source_path )
        print( " [I] Path Created: '" + source_path )

    # Create the output compiled path if it doesn't exist
    if not os.path.exists( compiled_path ):
        os.makedirs( compiled_path )
        print( " [I] Path Created: '" + compiled_path )


    # Save config
    if platform.system() == "Linux":
        # create the output compiled path if it doesn't exist
        if not os.path.exists( "/etc/veil/" ):
            os.makedirs( "/etc/veil/" )
            print( " [I] Path '/etc/veil/' Created" )
        f = open( "/etc/veil/settings.py", 'w' )
        f.write( config )
        f.close()
        os.chmod( "/etc/veil/settings.py", 0o0755 )
        print( " [I] Configuration File Written To: '/etc/veil/settings.py'\n" )
    else:
        print( " [!] ERROR: PLATFORM NOT CURRENTLY SUPPORTED" )
        sys.exit()


if __name__ == '__main__':

    options = {}

    # Check for root access
    if os.geteuid() != 0:
        print( "\n [!] ERROR: Not root. Requesting...\n" )
        os.execvp( "sudo", ["sudo"] + ["python"] + sys.argv )
        sys.exit()

    if platform.system() == "Linux":
        # Check /etc/issue for the exact linux distro
        issue = open( "/etc/issue" ).read()

        # General options
        options["METASPLOIT_PATH"] = "/opt/metasploit-framework/embedded/framework/"
        options["MSFVENOM_OPTIONS"] = ""
        options["MSFVENOM_PATH"] = "/usr/local/bin/"
        options["OPERATING_SYSTEM"] = "Linux"
        options["PYINSTALLER_PATH"] = "/var/lib/veil/PyInstaller-3.2.1/" # via /config/setup.sh
        options["GOLANG_PATH"] = "/var/lib/veil/go/" # via /config/setup.sh
        options["TEMP_PATH"] = "/tmp/"
        options["TERMINAL_CLEAR"] = "clear"
        options["WINEPREFIX"] = "/var/lib/veil/wine/"
        VEIL_PATH = "/".join( os.getcwd().split( "/" )[:-1] ) + "/"
        options["VEIL_PATH"] = VEIL_PATH

        # Veil-Evasion specific options
        options["HANDLER_PATH"] = "/var/lib/veil/output/handlers/"
        options["HASH_LIST"] = "/var/lib/veil/output/hashes.txt"
        options["PAYLOAD_COMPILED_PATH"] = "/var/lib/veil/output/compiled/"
        options["PAYLOAD_SOURCE_PATH"] = "/var/lib/veil/output/source/"

        # Kali
        if issue.startswith( ("Kali", "Parrot") ):
            options["OPERATING_SYSTEM"] = "Kali"
            options["METASPLOIT_PATH"] = "/usr/share/metasploit-framework/"
            options["MSFVENOM_PATH"] = "/usr/bin/"
            options["TERMINAL_CLEAR"] = "false"
        # BackTrack
        elif issue.startswith( "BackTrack" ):
            options["OPERATING_SYSTEM"] = "BackTrack"
            options["METASPLOIT_PATH"] = "/opt/metasploit/msf3/"
            options["MSFVENOM_PATH"] = "/opt/metasploit/msf3/"

        # Check the paths are correct (WINEPREFIX)
        while not os.path.isdir( options["TEMP_PATH"] ):
            path = input( " [>] Please enter the directory of your system's temp path (e.g. /tmp/): " )
            path = str(path)
            options["TEMP_PATH"] = path
        if not options["TEMP_PATH"].endswith('/'):
            options["TEMP_PATH"] += "/"

        # Check the paths are correct (METASPLOIT_PATH)
        while not os.path.isdir( options["METASPLOIT_PATH"] ):
            path = input( " [>] Please enter the directory of the Metasploit Framework (e.g. %s): " % ( options["METASPLOIT_PATH"] ) )
            path = str(path)
            options["METASPLOIT_PATH"] = path
        if not options["METASPLOIT_PATH"].endswith('/'):
            options["METASPLOIT_PATH"] += "/"

        # Check the paths are correct (MSFVENOM_PATH)
        while not os.path.isfile( options["MSFVENOM_PATH"] + "/msfvenom" ):
            path = input( " [>] Please enter the directory of msfvenom (e.g. /usr/bin/): " )
            path = str(path)
            options["MSFVENOM_PATH"] = path
        if not options["MSFVENOM_PATH"].endswith('/'):
            options["MSFVENOM_PATH"] += "/"

        # Check the paths are correct (VEIL_PATH)
        while not os.path.isdir( options["VEIL_PATH"] ):
            print( "\n [i] Can't find Veil's path?   Run: %s --force --silent" % ( os.path.abspath("./config/setup.sh" ) ) )
            path = str(path)
            path = input( " [>] Please enter the directory to Veil (e.g. /opt/veil/): " )
            options["VEIL_PATH"] = path
        if not options["VEIL_PATH"].endswith('/'):
            options["VEIL_PATH"] += "/"

        # Check the paths are correct (PYINSTALLER_PATH)
        while not os.path.isdir( options["PYINSTALLER_PATH"] ):
            print( "\n [i] Can't find PyInstaller?   Run: %s --force --silent" % ( os.path.abspath("./config/setup.sh" ) ) )
            path = input( " [>] Please enter the directory of PyInstaller (e.g. %s): " % ( options["PYINSTALLER_PATH"] ) )
            path = str(path)
            options["PYINSTALLER_PATH"] = path
        if not options["PYINSTALLER_PATH"].endswith('/'):
            options["PYINSTALLER_PATH"] += "/"

        # Check the paths are correct (WINEPREFIX)
        while not os.path.isdir( options["WINEPREFIX"] ):
            print( "\n [i] Can't find WINE profile?   Run: %s --force --silent" % ( os.path.abspath("./config/setup.sh" ) ) )
            path = input( " [>] Please enter the directory of Veil's WINE profile (e.g. %s): " % ( options["WINEPREFIX"] ) )
            path = str(path)
            options["WINEPREFIX"] = path
        if not options["WINEPREFIX"].endswith('/'):
            options["WINEPREFIX"] += "/"

        # Check the paths are correct (GOLANG_PATH)
        while not os.path.isdir( options["GOLANG_PATH"] ):
            print( "\n [i] Can't find GoLang?   Run: %s --force --silent" % ( os.path.abspath("./config/setup.sh" ) ) )
            path = input( " [>] Please enter the directory of GoLang (e.g. %s): " % ( options["GOLANG_PATH"] ) )
            path = str(path)
            options["GOLANG_PATH"] = path
        if not options["GOLANG_PATH"].endswith('/'):
            options["GOLANG_PATH"] += "/"
    # Unsupported platform...
    else:
        print( " [!] ERROR: PLATFORM NOT CURRENTLY SUPPORTED" )
        sys.exit()

    generateConfig( options )
