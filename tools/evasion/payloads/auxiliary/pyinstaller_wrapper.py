"""
Simple auxiliary module that will take a specified python source
file and compile it to an executable using PyInstaller.

Module built by @harmj0y
"""

from lib.common import helpers
from tools.evasion.evasion_common import encryption


class PayloadModule:

    def __init__(self, cli_obj):

        # required options
        self.description = "Auxiliary pyinstaller wrapper for python source files"
        self.language = "python"
        self.rating = "Normal"
        self.extension = "py"
        self.name = "PyInstaller Wrapper"
        self.path = "auxuliary/pyinstaller_wrapper"
        self.cli_opts = cli_obj
        self.payload_source_code = ""

        self.required_options = {
                                    "PYTHON_SOURCE" : ["", "A Python source file to compile with pyinstaller"],   # /path/to/any/python/file.py
                                    "COMPILE_TO_EXE" : ["Y", "Compile to an executable"],
                                    "USE_PYHERION"   : ["N", "Use the pyherion encrypter"]
                                }

    def generate(self):

        PYTHON_SOURCE = self.required_options["PYTHON_SOURCE"][0]

        try:
            # read in the python source
            with open(PYTHON_SOURCE, 'r') as f:
                payload_code = f.read()

        except IOError:
            print(helpers.color("\n [!] PYTHON_SOURCE file \"" + PYTHON_SOURCE + "\" not found\n", warning=True))
            return ""

        # example of how to check the internal options
        if self.required_options["USE_PYHERION"][0].lower() == "y":
            payload_code = encryption.pyherion(payload_code)

        # return everything
        self.payload_source_code = payload_code
        return
