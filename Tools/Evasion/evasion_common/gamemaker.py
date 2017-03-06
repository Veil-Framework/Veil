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
        if evasion_payload.required_options["EXPIRE_PAYLOAD"][0].lower() != "x":

            year = date.today().year
            month = date.today().month
            day = date.today().day

            # Create Payload code
            check_code += 'require \'date\'\n'
            check_code += 'if Date.today < Date.parse(\'' + year + '-' + month + '-' + day + '\').next_day(' + evasion_payload.required_options["EXPIRE_PAYLOAD"][0] + ')\n'

            # Add a tab for this check
            num_tabs_required += 1

        if evasion_payload.required_options["HOSTNAME"][0].lower() != "x":

            check_code += 'require \'socket\'\n'
            check_code += 'hostname = Socket.gethostname.downcase\n'
            check_code += 'if hostname[\"' + evasion_payload.required_options["HOSTNAME"][0].lower() + '\"]\n'

            # Add a tab for this check
            num_tabs_required += 1

        if evasion_payload.required_options["DOMAIN"][0].lower() != "x":

            check_code += 'require \'socket\'\n'
            check_code += 'domain = Socket.gethostname.downcase\n'
            check_code += 'if domain[\"' + evasion_payload.required_options["DOMAIN"][0].lower() + '\"]\n'

            # Add a tab for this check
            num_tabs_required += 1

        if evasion_payload.required_options["USERNAME"][0].lower() != "x":

            check_code += 'name = ENV["USERNAME"].downcase\n'
            check_code += 'if name[\"' + evasion_payload.required_options["USERNAME"][0].lower() + '\"]\n'

            # Add a tab for this check
            num_tabs_required += 1

        # Return check information
        return check_code, num_tabs_required

    elif evasion_payload.language == 'perl':
        if evasion_payload.required_options["HOSTNAME"][0].lower() != "x":

            rand_hostname = evasion_helpers.randomString()
            check_code += '\t' * num_tabs_required + 'Use Sys::Hostname;\n'
            check_code += '\t' * num_tabs_required + 'my $' + rand_hostname + ' = hostname;\n'
            check_code += '\t' * num_tabs_required + 'if (index(lc($' + rand_hostname + '), lc(' + evasion_payload.required_options["HOSTNAME"][0] + ')) != -1){\n'

            # Add a tab for this check
            num_tabs_required += 1

        if evasion_payload.required_options["USERNAME"][0].lower() != "x":

            rand_name = evasion_helpers.randomString()
            check_code += '\t' * num_tabs_required + 'my $' + rand_name + ' = Win32::LoginName;\n'
            check_code += '\t' * num_tabs_required + 'if (index(lc($' + rand_name + '), lc(\"' + evasion_payload.required_options["USERNAME"][0] + '\")) != -1){\n'

            # Add a tab for this check
            num_tabs_required += 1

        if evasion_payload.required_options["DOMAIN"][0].lower() != "x":

            rand_domain = evasion_helpers.randomString()
            check_code += '\t' * num_tabs_required + 'use Net::Domain qw (hostdomain);\n'
            check_code += '\t' * num_tabs_required + 'my $' + rand_domain + ' = hostdomain();\n'
            check_code += '\t' * num_tabs_required + 'if (index(lc($' + rand_domain + '), lc(\"' + evasion_payload.required_options["DOMAIN"][0] + '\")) != -1){\n'

            # Add a tab for this check
            num_tabs_required += 1

        if evasion_payload.required_options["PROCESSORS"][0].lower() != "x":

            rand_corecount = evasion_helpers.randomString()
            check_code += '\t' * num_tabs_required + 'my $' + rand_corecount + ' = $ENV{\"NUMBER_OF_PROCESSORS\"};'
            check_code += '\t' * num_tabs_required + 'if ($' + rand_corecount + ' >=  '+ evasion_payload.required_options["PROCESSORS"][0] + '){\n'

            # Add a tab for this check
            num_tabs_required += 1

        # Return check information
        return check_code, num_tabs_required

    elif evasion_payload.language == 'powershell':
        if evasion_payload.required_options["HOSTNAME"][0].lower() != "x":
            check_code += "if($env:computername -eq \"" + evasion_payload.required_options["HOSTNAME"][0].lower() + "\") {\n"
            num_tabs_required += 1

        if evasion_payload.required_options["DOMAIN"][0].lower() != "x":
            check_code += "if((Get-WMIObject -Class Win32_ComputerSystem).Domain -eq \"" + evasion_payload.required_options["DOMAIN"][0].lower() + "\") {\n"
            num_tabs_required += 1

        if evasion_payload.required_options["USERNAME"][0].lower() != "x":
            check_code += "if($env:username -eq \"" + evasion_payload.required_options["USERNAME"][0].lower() + "\") {\n"
            num_tabs_required += 1

        if evasion_payload.required_options["PROCESSORS"][0].lower() != "x":
            check_code += "if((Get-WMIObject -Class Win32_Processor).NumberOfLogicalProcessors -ge " + evasion_payload.required_options["PROCESSORS"][0].lower() + ") {\n"
            num_tabs_required += 1

        # Return check information
        return check_code, num_tabs_required

    elif evasion_payload.language == 'cs':
        if evasion_payload.required_options["EXPIRE_PAYLOAD"][0].lower() != "x":

            RandToday = evasion_helpers.randomString()
            RandExpire = evasion_helpers.randomString()

            # Create Payload code
            check_code += '\t' * num_tabs_required + 'DateTime {} = DateTime.Today;\n'.format(RandToday)
            check_code += '\t' * num_tabs_required + 'DateTime {} = {}.AddDays({});\n'.format(RandExpire, RandToday, evasion_payload.required_options["EXPIRE_PAYLOAD"][0])
            check_code += '\t' * num_tabs_required + 'if ({} < {}) {{\n'.format(RandExpire, RandToday)

            # Add a tab for this check
            num_tabs_required += 1

        if evasion_payload.required_options["HOSTNAME"][0].lower() != "x":

            check_code += '\t' * num_tabs_required + 'if (System.Environment.MachineName.ToLower().Contains("{}")) {{\n'.format(evasion_payload.required_options["HOSTNAME"][0].lower())            

            # Add a tab for this check
            num_tabs_required += 1

        if evasion_payload.required_options["DOMAIN"][0].lower() != "x":

            check_code += '\t' * num_tabs_required + 'if (System.Environment.MachineName.ToLower() != System.Environment.UserDomainName.ToLower()) {\n'                        

            # Add a tab for this check
            num_tabs_required += 1

        if evasion_payload.required_options["PROCESSORS"][0].lower() != "x":

            check_code += '\t' * num_tabs_required + 'if (System.Environment.ProcessorCount > {}) {{\n'.format(evasion_payload.required_options["PROCESSORS"][0])

            # Add a tab for this check
            num_tabs_required += 1

        if evasion_payload.required_options["USERNAME"][0].lower() != "x":

            rand_user_name = evasion_helpers.randomString()
            rand_char_name = evasion_helpers.randomString()
            check_code += '\t' * num_tabs_required + 'string {} = System.Security.Principal.WindowsIdentity.GetCurrent().Name;\n'.format(rand_user_name)
            check_code += '\t' * num_tabs_required + "string[] {} = {}.Split('\\\\');\n".format(rand_char_name, rand_user_name)
            check_code += '\t' * num_tabs_required + 'if ({}[1].Contains("{}")) {{\n\n'.format(rand_char_name, evasion_payload.required_options["USERNAME"][0])            

            # Add a tab for this check
            num_tabs_required += 1

        # Return check information
        return check_code, num_tabs_required

    elif evasion_payload.language == 'go':
        rand_username = evasion_helpers.randomString()
        rand_error1 = evasion_helpers.randomString()
        rand_hostname = evasion_helpers.randomString()
        rand_error2 = evasion_helpers.randomString()
        rand_processor = evasion_helpers.randomString()
        rand_domain = evasion_helpers.randomString()

        if evasion_payload.required_options["USERNAME"][0].lower() != "x":
            check_code += rand_username + ", " + rand_error1 + " := user.Current()\n"
            check_code += "if " + rand_error1 + " != nil {\n"
            check_code += "os.Exit(1)}\n"
            check_code += "if strings.Contains(strings.ToLower(" + rand_username + ".Username), strings.ToLower(\"" + evasion_payload.required_options["USERNAME"][0] + "\")) {\n"
            num_tabs_required += 1

        if evasion_payload.required_options["HOSTNAME"][0].lower() != "x":
            check_code += rand_hostname + ", " + rand_error2 + " := os.Hostname()\n"
            check_code += "if " + rand_error2 + " != nil {\n"
            check_code += "os.Exit(1)}\n"
            check_code += "if strings.Contains(strings.ToLower(" + rand_hostname + "), strings.ToLower(\"" + evasion_payload.required_options["HOSTNAME"][0] + "\")) {\n"
            num_tabs_required += 1

        if evasion_payload.required_options["PROCESSORS"][0].lower() != "x":
            check_code += rand_processor + " := runtime.NumCPU()\n"
            check_code += "if " + rand_processor + " >= " + evasion_payload.required_options["PROCESSORS"][0] + " {\n"
            num_tabs_required += 1

        # Return check information
        return check_code, num_tabs_required

    else:
        return '', 0
