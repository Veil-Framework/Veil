#!/usr/bin/python

import platform, os, sys, pwd

"""

Take an options dictionary and update /etc/veil/settings.py

"""
def generateConfig(options):

    config = """#!/usr/bin/python

##################################################################################################
#
# Veil-Framework configuration file
#
# Run update.py to automatically set all these options to their defaults.
#
##################################################################################################



#################################################
#
# General system options
#
#################################################

"""
    print "\n Veil-Framework configuration:"

    config += '# OS to use (Kali/Backtrack/Debian/Windows)\n'
    config += 'OPERATING_SYSTEM="' + options['OPERATING_SYSTEM'] + '"\n\n'
    print "\n [*] OPERATING_SYSTEM = " + options['OPERATING_SYSTEM']

    config += '# Specific Linux distro\n'
    # check /etc/issue for the exact linux distro
    issue = open("/etc/issue").read()
    if issue.startswith("Debian"):
        config += 'DISTRO="Debian"\n\n'
    else:
        config += 'DISTRO="Linux"\n\n'

    config += '# Terminal clearing method to use (use "false" to disable it)\n'
    config += 'TERMINAL_CLEAR="' + options['TERMINAL_CLEAR'] + '"\n\n'
    print " [*] TERMINAL_CLEAR = " + options['TERMINAL_CLEAR']

    config += '# Wine environment\n'
    config += 'WINEPREFIX="' + options["WINEPREFIX"] + '"\n\n'
    print " [*] WINEPREFIX = " + options["WINEPREFIX"]

    config += '# Path to temporary directory\n'
    config += 'TEMP_DIR="' + options["TEMP_DIR"] + '"\n\n'
    print " [*] TEMP_DIR = " + options["TEMP_DIR"]

    config += '# Default options to pass to msfvenom for shellcode creation\n'
    config += 'MSFVENOM_OPTIONS="' + options['MSFVENOM_OPTIONS'] + '"\n\n'
    print " [*] MSFVENOM_OPTIONS = " + options['MSFVENOM_OPTIONS']

    config += '# The path to the metasploit framework, for example: /usr/share/metasploit-framework/\n'
    config += 'METASPLOIT_PATH="' + options['METASPLOIT_PATH'] + '"\n\n'
    print " [*] METASPLOIT_PATH = " + options['METASPLOIT_PATH']

    config += '# The path to msfvenom for shellcode generation purposes\n'
    config += 'MSFVENOM_PATH="' + options["MSFVENOM_PATH"] + '"\n\n'
    print " [*] MSFVENOM_PATH = " + options["MSFVENOM_PATH"]

    config += '# The path to pyinstaller, for example: /opt/pyinstaller-2.0/\n'
    config += 'PYINSTALLER_PATH="' + options['PYINSTALLER_PATH'] + '"\n\n'
    print " [*] PYINSTALLER_PATH = " + options['PYINSTALLER_PATH'] + "\n"


    config += """
#################################################
#
# Veil-Evasion specific options
#
#################################################

"""
    config += '# Veil-Evasion install path\n'
    config += 'VEIL_EVASION_PATH="' + options['VEIL_EVASION_PATH'] + '"\n\n'
    print " [*] VEIL_EVASION_PATH = " + options['VEIL_EVASION_PATH']

    source_path = os.path.expanduser(options["PAYLOAD_SOURCE_PATH"])
    config += '# Path to output the source of payloads\n'
    config += 'PAYLOAD_SOURCE_PATH="' + source_path + '"\n\n'
    print " [*] PAYLOAD_SOURCE_PATH = " + source_path

    # create the output source path if it doesn't exist
    if not os.path.exists(source_path):
        os.makedirs(source_path)
        print " [*] Path '" + source_path + "' Created"

    compiled_path = os.path.expanduser(options["PAYLOAD_COMPILED_PATH"])
    config += '# Path to output compiled payloads\n'
    config += 'PAYLOAD_COMPILED_PATH="' + compiled_path +'"\n\n'
    print " [*] PAYLOAD_COMPILED_PATH = " + compiled_path

    # create the output compiled path if it doesn't exist
    if not os.path.exists( compiled_path ):
        os.makedirs( compiled_path )
        print " [*] Path '" + compiled_path + "' Created"

    handler_path = os.path.expanduser(options["HANDLER_PATH"])
    # create the output compiled path if it doesn't exist
    if not os.path.exists( handler_path ):
        os.makedirs( handler_path )
        print " [*] Path '" + handler_path + "' Created"

    config += '# Whether to generate a msf handler script and where to place it\n'
    config += 'GENERATE_HANDLER_SCRIPT="' + options['GENERATE_HANDLER_SCRIPT'] + '"\n'
    print " [*] GENERATE_HANDLER_SCRIPT = " + options['GENERATE_HANDLER_SCRIPT']
    config += 'HANDLER_PATH="' + handler_path + '"\n\n'
    print " [*] HANDLER_PATH = " + handler_path

    hash_path = os.path.expanduser(options["HASH_LIST"])
    config += '# Running hash list of all payloads generated\n'
    config += 'HASH_LIST="' + hash_path + '"\n\n'
    print " [*] HASH_LIST = " + hash_path + "\n"


    config += """
#################################################
#
# Veil-Catapult specific options
#
#################################################

"""
    config += '# Veil-Catapult install path\n'
    config += 'VEIL_CATAPULT_PATH="' + options['VEIL_CATAPULT_PATH'] + '"\n\n'
    print " [*] VEIL_CATAPULT_PATH = " + options['VEIL_CATAPULT_PATH']

    catapult_resource_path = os.path.expanduser(options["CATAPULT_RESOURCE_PATH"])
    # create the catapult resource path if it doesn't exist
    if not os.path.exists( catapult_resource_path ):
        os.makedirs( catapult_resource_path )
        print " [*] Path '" + catapult_resource_path + "' Created"
    config += '# Path to output Veil-Catapult resource/cleanup files\n'
    config += 'CATAPULT_RESOURCE_PATH="' + catapult_resource_path + '"\n\n'
    print " [*] CATAPULT_RESOURCE_PATH = " + catapult_resource_path + "\n"


    if platform.system() == "Linux":
        # create the output compiled path if it doesn't exist
        if not os.path.exists("/etc/veil/"):
            # os.makedirs("/etc/veil/")
            os.system("sudo mkdir /etc/veil/")
            os.system("sudo touch /etc/veil/settings.py")
            os.system("sudo chmod 777 /etc/veil/settings.py")
            print " [*] Path '/etc/veil/' Created"
        f = open("/etc/veil/settings.py", 'w')
        f.write(config)
        f.close()
        print " Configuration File Written To '/etc/veil/settings.py'\n"
    else:
        print " [!] ERROR: PLATFORM NOT CURRENTLY SUPPORTED"
        sys.exit()


if __name__ == '__main__':

    options = {}

    if platform.system() == "Linux":

        # check /etc/issue for the exact linux distro
        issue = open("/etc/issue").read()

        if issue.startswith("Kali"):
            options["OPERATING_SYSTEM"] = "Kali"
            options["TERMINAL_CLEAR"] = "clear"
            options["METASPLOIT_PATH"] = "/usr/share/metasploit-framework/"
            if os.path.isfile('/usr/bin/msfvenom'):
                options["MSFVENOM_PATH"] = "/usr/bin/"
            else:
                msfpath = raw_input(" [>] Please enter the path of your metasploit installation: ")
                options["MSFVENOM_PATH"] = msfpath
            if os.path.isdir('/opt/veil/PyInstaller-3.2.1/'):
                options["PYINSTALLER_PATH"] = "/opt/veil/PyInstaller-3.2.1/"
            else:
                options["PYINSTALLER_PATH"] = "/opt/veil/PyInstaller-3.2.1/"
        elif issue.startswith("BackTrack"):
            options["OPERATING_SYSTEM"] = "BackTrack"
            options["TERMINAL_CLEAR"] = "clear"
            options["METASPLOIT_PATH"] = "/opt/metasploit/msf3/"
            if os.path.isfile('/usr/bin/msfvenom'):
                options["MSFVENOM_PATH"] = "/usr/bin/"
            else:
                options["MSFVENOM_PATH"] = "/opt/metasploit/msf3/"
            options["PYINSTALLER_PATH"] = "/opt/veil/PyInstaller-3.2.1/"
        else:
            options["OPERATING_SYSTEM"] = "Linux"
            options["TERMINAL_CLEAR"] = "clear"
            msfpath = raw_input(" [>] Please enter the path of your metasploit installation: ")
            options["METASPLOIT_PATH"] = msfpath
            if os.path.isfile('/usr/bin/msfvenom'):
                options["MSFVENOM_PATH"] = "/usr/bin/"
            else:
                options["MSFVENOM_PATH"] = msfpath
            options["PYINSTALLER_PATH"] = "/opt/veil/PyInstaller-3.2.1/"

        # last of the general options
        options["TEMP_DIR"] = "/tmp/"
        options["MSFVENOM_OPTIONS"] = ""

        # Get the real user if we're being ran under sudo
        wineprefix = ""
        user = os.environ.get("SUDO_USER", pwd.getpwuid(os.getuid()).pw_name)
        if user == 'root':
            wineprefix = "/root/.config/wine/veil/"
        else:
            wineprefix = "/home/" + user + "/.config/wine/veil/"
        options["WINEPREFIX"] = wineprefix

        # Veil-Evasion specific options
        veil_evasion_path = "/".join(os.getcwd().split("/")[:-1]) + "/"
        options["VEIL_EVASION_PATH"] = veil_evasion_path
        options["PAYLOAD_SOURCE_PATH"] = "/usr/share/veil-output/source/"
        options["PAYLOAD_COMPILED_PATH"] = "/usr/share/veil-output/compiled/"
        options["GENERATE_HANDLER_SCRIPT"] = "True"
        options["HANDLER_PATH"] = "/usr/share/veil-output/handlers/"
        options["HASH_LIST"] = "/usr/share/veil-output/hashes.txt"

        # Veil-Catapult specific options
        veil_catapult_path = "/".join(os.getcwd().split("/")[:-2]) + "/Veil-Catapult/"
        options["VEIL_CATAPULT_PATH"] = veil_catapult_path
        options["CATAPULT_RESOURCE_PATH"] = "/usr/share/veil-output/catapult/"


    # unsupported platform...
    else:
        print " [!] ERROR: PLATFORM NOT CURRENTLY SUPPORTED"
        sys.exit()

    generateConfig(options)
