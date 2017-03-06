"""

Description of the payload.


Addtional notes, sources, links, etc.


Author of the module.

"""

# framework import to access shellcode generation
from modules.common import shellcode

# framework import to access common helper methods, including randomization
from modules.common import helpers

# framework import to access encryption and source code obfuscation methods
from modules.common import encryption

# the main config file
import settings

# Main class must be titled "Payload"
class Payload:

    def __init__(self):
        # required options
        self.description = "description"
        self.language = "python/cs/powershell/whatever"
        self.rating = "Poor/Normal/Good/Excellent"
        self.extension = "py/cs/c/etc."

        self.shellcode = shellcode.Shellcode()
        # options we require user ineraction for- format is {OPTION : [Value, Description]]}
        # the code logic will parse any of these out and require the user to input a value for them
        self.required_options = {
                                    "COMPILE_TO_EXE" : ["Y", "Compile to an executable"],
                                    "USE_PYHERION"   : ["N", "Use the pyherion encrypter"]
                                }

        # an option note to be displayed to the user after payload generation
        # i.e. additional compile notes, or usage warnings
        self.notes = "...additional notes to user..."

    # main method that returns the generated payload code
    def generate(self):

        # Generate Shellcode Using msfvenom
        Shellcode = self.shellcode.generate(self.required_options)

        # build our your payload sourcecode
        PayloadCode = "..."

        # add in a randomized string
        PayloadCode += helpers.randomString()

        # example of how to check the internal options
        if self.required_options["USE_PYHERION"][0].lower() == "y":
            PayloadCode = encryption.pyherion(PayloadCode)

        # return everything
        return PayloadCode
