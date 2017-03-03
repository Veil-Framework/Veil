#!/usr/bin/env python3

import argparse
import sys
from lib.common import helpers
from lib.common import messages
from lib.common import orchestra
sys.dont_write_bytecode = True


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        add_help=False, description="Veil is a framework containing multiple\
         tools.")
    parser.add_argument(
        '-h', '-?', '--h', '-help', '--help', action="store_true",
        help=argparse.SUPPRESS)

    veilframework = parser.add_argument_group('Veil Options')
    veilframework.add_argument(
        '--update', action='store_true', help='Update the Veil framework.')
    veilframework.add_argument(
        '--version', action="store_true", help='Displays version and quits.')
    veilframework.add_argument(
        '--list-tools', action="store_true", default=False,
        help='List Veil\'s tools')
    veilframework.add_argument(
        '-t', '--tool', metavar='Veil-Framework', default=False,
        help='Specify Veil tool to use')

    callback_args = parser.add_argument_group('Callback Settings')
    callback_args.add_argument(
        "--ip", "--domain", metavar="IP Address", default=None,
        help="IP Address to connect back to")
    callback_args.add_argument(
        '--port', metavar="Port Number", default=8675, type=int,
        help="Port number to connect to.")

    veilevasion = parser.add_argument_group('Veil-Evasion Options')
    veilevasion.add_argument(
        '-c', metavar='OPTION1=value OPTION2=value', nargs='*',
        default=None, help='Custom payload module options.')
    veilevasion.add_argument(
        '-o', metavar="OUTPUT NAME", default="payload",
        help='Output file base name for source and compiled binaries.')
    veilevasion.add_argument(
        '-p', metavar="PAYLOAD", nargs='?', const="list",
        help='Payload to generate. Lists payloads if none specified.')
    veilevasion.add_argument(
        '--clean', action='store_true',
        help='Clean out payload folders.')
    veilevasion.add_argument(
        '--msfoptions', metavar="OPTION=value", nargs='*',
        help='Options for the specified metasploit payload.')
    veilevasion.add_argument(
        '--msfvenom', metavar="windows/meterpreter/reverse_tcp", nargs='?',
        default='windows/meterpreter/reverse_tcp', help='Metasploit shellcode to generate.')
    veilevasion.add_argument(
        '--compiler', metavar="pyinstaller", default='pyinstaller',
        help='Compiler option for payload (currently only needed for Python)')

    ordnance_shellcode = parser.add_argument_group('Veil-Ordnance Shellcode Options')
    ordnance_shellcode.add_argument(
        "--ordnance-payload", metavar="rev_tcp", default=None,
        help="Payload type (bind_tcp, rev_tcp, etc.)")
    ordnance_shellcode.add_argument(
        '--list-payloads', default=False, action='store_true',
        help="Lists all available payloads.")

    ordnance_encoder = parser.add_argument_group('Veil-Ordnance Encoder Options')
    ordnance_encoder.add_argument(
        "-e", "--encoder", metavar="Encoder Name", default=None,
        help="Name of Shellcode Encoder to use")
    ordnance_encoder.add_argument(
        "-b", "--bad-chars", metavar="\\\\x00\\\\x0a..", default=None,
        help="Bad characters to avoid")
    ordnance_encoder.add_argument(
        '--list-encoders', default=False, action='store_true',
        help="Lists all available encoders.")
    ordnance_encoder.add_argument(
        '--print-stats', default=False, action='store_true',
        help="Print information about the encoded shellcode.")

    args = parser.parse_args()

    the_conductor = orchestra.Conductor(args)

    if args.h:
        parser.print_help()
        sys.exit()

    if args.version:
        messages.title_screen()
        sys.exit()

    if args.update:
        the_conductor.update_veil()
        sys.exit()

    if args.list_tools:
        the_conductor.list_tools()
        sys.exit()

    if args.clean:
        helpers.clean_payloads()
        sys.exit()

    if not args.tool:
        the_conductor.main_menu()
        sys.exit()

    # This should hit if trying to use the CLI
    else:
        the_conductor.command_line_use()
