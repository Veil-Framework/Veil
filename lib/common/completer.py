"""

Contains any classes used for tab completion.


Reference - http://stackoverflow.com/questions/5637124/tab-completion-in-pythons-raw-input

"""

# Import Modules
import readline
import subprocess
import re
import os
import sys

# try to find and import the settings.py config file
if os.path.exists("/etc/veil/settings.py"):
    try:
        sys.path.append("/etc/veil/")
        import settings
    except:
        print("Error importing Veil Settings!")
        sys.exit(1)


class none(object):
    def complete(self, args):
        return [None]


class MainMenuCompleter(object):
    """
    Class used for tab completion of the main Controller menu

    Takes a list of available commands, and loaded payload modules.

    """
    def __init__(self, cmds, payloads):
        self.commands = [cmd for cmd, desc in cmds.items()]
        self.payloads = payloads

    def complete_use(self, args):
        """Complete payload/module"""

        res = []
        payloads = []

        for name, payload in self.payloads.items():
            payloads.append(name)

        # return all payloads if we just have "use"
        if len(args[0].split("/")) == 1:
            res = [m for m in payloads if m.startswith(args[0])] + [None]

        else:
            # get the language
            lang = args[0].split("/")[0]
            # get the rest of the paths
            rest = "/".join(args[0].split("/")[1:])

            payloads = []
            for name, payload in self.payloads.items():

                parts = name.split("/")

                # iterate down the split parts so we can handle the nested payload structure
                for x in range(0, len(parts)):

                    # if the first part of the iterated payload matches the language, append it
                    if parts[x] == lang:
                        payloads.append("/".join(parts[x + 1:]))

                res = [lang + '/' + m + ' ' for m in payloads if m.startswith(rest)] + [None]

        return res

    def complete_info(self, args):
        """Complete payload/module"""

        res = []
        payloads = []

        for (name, payload) in self.payloads:
            payloads.append(name)

        # return all payloads if we just have "use"
        if len(args[0].split("/")) == 1:
            res = [ m for m in payloads if m.startswith(args[0])] + [None]

        else:
            # get the language
            lang = args[0].split("/")[0]
            # get the rest of the paths
            rest = "/".join(args[0].split("/")[1:])

            payloads = []
            for (name, payload) in self.payloads:

                parts = name.split("/")

                # iterate down the split parts so we can handle the nested payload structure
                for x in xrange(len(parts)):

                    # if the first part of the iterated payload matches the language, append it
                    if parts[x] == lang:
                        payloads.append("/".join(parts[ x+ 1:]))

                res = [lang + '/' + m + ' ' for m in payloads if m.startswith(rest)] + [None]

        return res

    def complete(self, text, state):

        "Generic readline completion entry point."
        buffer = readline.get_line_buffer()
        line = readline.get_line_buffer().split()

        # show all commands
        if not line:
            return [c + ' ' for c in self.commands][state]

        # account for last argument ending in a space
        RE_SPACE = re.compile('.*\s+$', re.M)
        if RE_SPACE.match(buffer):
            line.append('')

        # resolve command to the implementation functions (above)
        cmd = line[0].strip()
        if cmd in self.commands:
            impl = getattr(self, 'complete_%s' % cmd)
            args = line[1:]
            if args:
                return (impl(args) + [None])[state]
            return [cmd + ' '][state]

        results = [c + ' ' for c in self.commands if c.startswith(cmd)] + [None]

        return results[state]


class PayloadCompleter(object):

    def __init__(self, cmds, payload):
        self.commands = [cmd for cmd, desc in cmds.items()]
        self.payload = payload

    def _listdir(self, root):
        """
        Complete a directory path.
        """
        res = []
        for name in os.listdir(root):
            path = os.path.join(root, name)
            if os.path.isdir(path):
                name += os.sep
            res.append(name)
        return res

    def _complete_path(self, path=None):
        """
        Complete a file path.
        """
        if not path:
            return self._listdir('.')
        dirname, rest = os.path.split(path)
        tmp = dirname if dirname else '.'
        res = [os.path.join(dirname, p)
               for p in self._listdir(tmp) if p.startswith(rest)]
        # more than one match, or single match which does not exist (typo)
        if len(res) > 1 or not os.path.exists(path):
            return res
        # resolved to a single directory, so return list of files below it
        if os.path.isdir(path):
            return [os.path.join(path, p) for p in self._listdir(path)]
        # exact file match terminates this completion
        return [path + ' ']

    def complete_path(self, args):
        """
        Entry point for path completion.
        """
        if not args:
            return self._complete_path('.')
        # treat the last arg as a path and complete it
        return self._complete_path(args[-1])

    def complete_set(self, args):
        """
        Complete all options for the 'set' command.
        """

        res = []

        if hasattr(self.payload, 'required_options'):

            options = [k for k in sorted(self.payload.required_options.keys())]

            if args[0] != "":
                if args[0].strip() == "LHOST":
                    # autocomplete the IP for LHOST
                    if settings.DISTRO == 'Debian':
                        ip_output = subprocess.getoutput("ip a").split("\n")[8][9:].split('/')[0]
                    ip_output = subprocess.getoutput("/sbin/ifconfig eth0").split("\n")[1].split()[1]
                    if 'addr' in ip_output:
                        ip_output = ip_output[5:]
                    res = [ip_output] + [None]
                elif args[0].strip() == "LPORT":
                    # autocomplete the common MSF port of 4444 for LPORT
                    res = ["4444"] + [None]
                elif args[0].strip() == "original_exe":
                    # tab-complete a file path for an exe
                    res = self.complete_path(args)
                elif args[0].strip().endswith("_source"):
                    # tab-complete a file path for an exe
                    res = self.complete_path(args)
                # elif args[0].strip() == "other path-needing option":
                #     # tab-complete a file path
                #     res = self.complete_path(args)
                else:
                    # complete the command in the list ONLY if it's partially completed
                    res = [o + ' ' for o in options if (o.startswith(args[0]) and o != args[0])] + [None]
            else:
                # return all required_options available to 'set'
                res = [o + ' ' for o in options] + [None]

        return res

    def complete(self, text, state):
        """
        Generic readline completion entry point.
        """

        buffer = readline.get_line_buffer()
        line = readline.get_line_buffer().split()

        # show all commands
        if not line:
            return [c + ' ' for c in self.commands][state]

        # account for last argument ending in a space
        RE_SPACE = re.compile('.*\s+$', re.M)
        if RE_SPACE.match(buffer):
            line.append('')

        # resolve command to the implementation functions (above)
        cmd = line[0].strip()
        if cmd in self.commands:
            impl = getattr(self, 'complete_%s' % cmd)
            args = line[1:]
            if args:
                return (impl(args) + [None])[state]
            return [cmd + ' '][state]

        results = [c + ' ' for c in self.commands if c.startswith(cmd)] + [None]

        return results[state]


class MSFCompleter(object):
    """
    Class used for tab completion of metasploit payload selection.
    Used in ./modules/common/shellcode.py

    Takes a payloadTree next dictionary as an instantiation argument, of the form
        payloadTree = {"windows" : {"meterpreter", "shell",...}, "linux" : {...}}

    """
    def __init__(self, payloadTree):
        self.payloadTree = payloadTree

    def complete(self, text, state):

        buffer = readline.get_line_buffer()
        line = readline.get_line_buffer().split()

        # extract available platforms from the payload tree
        platforms = [k for k, v in self.payloadTree.items()]

        # show all platforms
        if not line:
            return [p + '/' for p in platforms][state]

        # account for last argument ending in a space
        RE_SPACE = re.compile('.*\s+$', re.M)
        if RE_SPACE.match(buffer):
            line.append('')

        i = line[0].strip()

        # complete the platform
        if len(i.split("/")) == 1:
            results = [p + '/' for p in platforms if p.startswith(i)] + [None]
            return results[state]

        # complete the stage, including singles (no /)
        elif len(i.split("/")) == 2:
            platform = i.split("/")[0]
            stage = i.split("/")[1]
            stages = [k for  k, v in self.payloadTree[platform].items()]
            results = [platform + "/" + s + '/' for s in stages if s.startswith(stage) and type(self.payloadTree[platform][s]) is dict]
            singles = [platform + "/" + s + ' ' for s in stages if s.startswith(stage) and type(self.payloadTree[platform][s]) is not dict]
            results += singles + [None]
            return results[state]

        # complete the stage (for x64) or stager (for x86)
        elif len(i.split("/")) == 3:

            platform = i.split("/")[0]
            stage = i.split("/")[1]
            stager = i.split("/")[2]

            stagers = [k for k, v in self.payloadTree[platform][stage].items()]

            results = [platform + "/" + stage + '/' + s + '/' for s in stagers if s.startswith(stager) and type(self.payloadTree[platform][stage][s]) is dict]
            singles = [platform + "/" + stage + '/' + s + ' ' for s in stagers if s.startswith(stager) and type(self.payloadTree[platform][stage][s]) is not dict]
            results += singles + [None]

            return results[state]

        # complete the stager for x64 (i.e. reverse_tcp)
        elif len(i.split("/")) == 4:

            platform = i.split("/")[0]
            arch = i.split("/")[1]
            stage = i.split("/")[2]
            stager = i.split("/")[3]

            stagers = [k for k, v in self.payloadTree[platform][arch][stage].items()]

            results = [platform + "/" + arch + "/" + stage + '/' + s for s in stagers if s.startswith(stager)] + [None]
            return results[state]

        else:
            return ""


class IPCompleter(object):
    """
    Class used for tab completion of local IP for LHOST.

    """
    def __init__(self):
        pass

    """
    If blank line, fill in the local IP
    """
    def complete(self, text, state):

        buffer = readline.get_line_buffer()
        line = readline.get_line_buffer().split()

        if not line:
            if settings.DISTRO == 'Debian':
                ip[state] = subprocess.getoutput("ip a").split("\n")[8][9:].split('/')[0]
            else:
                ip = [subprocess.getoutput("/sbin/ifconfig eth0").split("\n")[1].split()[1]] + [None]
                if 'addr' in ip[state]:
                    ip[state] = ip[state][5:]
            return ip[state]
        else:
            return text[state]


class MSFPortCompleter(object):
    """
    Class used for tab completion of the default port (4444) for MSF payloads

    """
    def __init__(self):
        pass

    """
    If blank line, fill in 4444
    """
    def complete(self, text, state):

        buffer = readline.get_line_buffer()
        line = readline.get_line_buffer().split()

        if not line:
            port = ["4444"] + [None]
            return port[state]
        else:
            return text[state]


class PathCompleter(object):
    """
    Class used for tab completion of files on the local path.
    """
    def __init__(self):
        pass

    def _listdir(self, root):
        res = []
        for name in os.listdir(root):
            path = os.path.join(root, name)
            if os.path.isdir(path):
                name += os.sep
            res.append(name)
        return res

    def _complete_path(self, path=None):
        if not path:
            return self._listdir('.')
        dirname, rest = os.path.split(path)
        tmp = dirname if dirname else '.'
        res = [os.path.join(dirname, p)
               for p in self._listdir(tmp) if p.startswith(rest)]
        # more than one match, or single match which does not exist (typo)
        if len(res) > 1 or not os.path.exists(path):
            return res
        # resolved to a single directory, so return list of files below it
        if os.path.isdir(path):
            return [os.path.join(path, p) for p in self._listdir(path)]
        # exact file match terminates this completion
        return [path + ' ']

    def complete_path(self, args):
        if not args:
            return self._complete_path('.')
        # treat the last arg as a path and complete it
        return self._complete_path(args[-1])

    def complete(self, text, state):

        buffer = readline.get_line_buffer()
        line = readline.get_line_buffer().split()

        return (self.complete_path(line) + [None])[state]


class OrdnanceCompleter(object):

    def __init__(self, cmds, payload):
        self.commands = [cmd for cmd, desc in cmds.items()]
        self.payload = payload

    def _listdir(self, root):
        """
        Complete a directory path.
        """
        res = []
        for name in os.listdir(root):
            path = os.path.join(root, name)
            if os.path.isdir(path):
                name += os.sep
            res.append(name)
        return res

    def _complete_path(self, path=None):
        """
        Complete a file path.
        """
        if not path:
            return self._listdir('.')
        dirname, rest = os.path.split(path)
        tmp = dirname if dirname else '.'
        res = [os.path.join(dirname, p)
               for p in self._listdir(tmp) if p.startswith(rest)]
        # more than one match, or single match which does not exist (typo)
        if len(res) > 1 or not os.path.exists(path):
            return res
        # resolved to a single directory, so return list of files below it
        if os.path.isdir(path):
            return [os.path.join(path, p) for p in self._listdir(path)]
        # exact file match terminates this completion
        return [path + ' ']

    def complete_path(self, args):
        """
        Entry point for path completion.
        """
        if not args:
            return self._complete_path('.')
        # treat the last arg as a path and complete it
        return self._complete_path(args[-1])

    def complete_set(self, args):
        """
        Complete all options for the 'set' command.
        """

        res = []

        if hasattr(self.payload, 'required_options'):

            options = [k for k in sorted(self.payload.required_options.keys())]

            if args[0] != "":
                if args[0].strip() == "LHOST":
                    if settings.DISTRO == 'Debian':
                        ip_output = subprocess.getoutput("ip a").split("\n")[8][9:].split('/')[0]
                    # autocomplete the IP for LHOST
                    else:
                        ip_output = subprocess.getoutput("/sbin/ifconfig eth0").split("\n")[1].split()[1]
                        if 'addr' in ip_output:
                            ip_output = ip_output[5:]
                    res = [ip_output] + [None]
                elif args[0].strip() == "LPORT":
                    # autocomplete the common MSF port of 4444 for LPORT
                    res = ["8675"] + [None]
                elif args[0].strip() == "original_exe":
                    # tab-complete a file path for an exe
                    res = self.complete_path(args)
                elif args[0].strip().endswith("_source"):
                    # tab-complete a file path for an exe
                    res = self.complete_path(args)
                # elif args[0].strip() == "other path-needing option":
                #     # tab-complete a file path
                #     res = self.complete_path(args)
                else:
                    # complete the command in the list ONLY if it's partially completed
                    res = [o + ' ' for o in options if (o.startswith(args[0]) and o != args[0])] + [None]
            else:
                # return all required_options available to 'set'
                res = [o + ' ' for o in options] + [None]

        return res

    def complete(self, text, state):
        """
        Generic readline completion entry point.
        """

        buffer = readline.get_line_buffer()
        line = readline.get_line_buffer().split()

        # show all commands
        if not line:
            return [c + ' ' for c in self.commands][state]

        # account for last argument ending in a space
        RE_SPACE = re.compile('.*\s+$', re.M)
        if RE_SPACE.match(buffer):
            line.append('')

        # resolve command to the implementation functions (above)
        cmd = line[0].strip()
        if cmd in self.commands:
            impl = getattr(self, 'complete_%s' % cmd)
            args = line[1:]
            if args:
                return (impl(args) + [None])[state]
            return [cmd + ' '][state]

        results = [c + ' ' for c in self.commands if c.startswith(cmd)] + [None]

        return results[state]


class VeilMainMenuCompleter(object):
    """
    Class used for tab completion of the main Controller menu

    Takes a list of available commands, and loaded payload modules.

    """
    def __init__(self, cmds, tools):
        self.commands = [cmd for cmd, desc in cmds.items()]
        self.tools = [obj.cli_name for name, obj in tools.items()]

    def complete_use(self, args):
        """Complete payload/module"""

        res = []
        tools = []

        for name in self.tools:
            tools.append(name)

        # return all payloads if we just have "use"
        if len(args[0]) == 0:
            res = [m for m in tools] + [None]

        else:
            tools = []
            for name in self.tools:
                if name.lower().startswith(args[0].lower()):
                    return [name + ' '] + [None]

        return res

    def complete_info(self, args):
        """Complete payload/module"""

        res = []
        tools = []

        for name in self.tools:
            tools.append(name)

        # return all payloads if we just have "use"
        if len(args[0]) == 0:
            res = [m for m in tools] + [None]

        else:
            tools = []
            for name in self.tools:
                if name.lower().startswith(args[0].lower()):
                    return [name + ' '] + [None]

        return res

    def complete(self, text, state):

        "Generic readline completion entry point."
        buffer = readline.get_line_buffer()
        line = readline.get_line_buffer().split()

        # show all commands
        if not line:
            return [c + ' ' for c in self.commands][state]

        # account for last argument ending in a space
        RE_SPACE = re.compile('.*\s+$', re.M)
        if RE_SPACE.match(buffer):
            line.append('')

        # resolve command to the implementation functions (above)
        cmd = line[0].strip()
        if cmd in self.commands:
            impl = getattr(self, 'complete_%s' % cmd)
            args = line[1:]
            if args:
                return (impl(args) + [None])[state]
            return [cmd + ' '][state]

        results = [c + ' ' for c in self.commands if c.startswith(cmd)] + [None]

        return results[state]
