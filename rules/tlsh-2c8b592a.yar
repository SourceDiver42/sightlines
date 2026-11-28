rule Sightlines_tlsh_2c8b592a_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-2c8b592a"
        date = "2026-11-23"
        campaign = "tlsh-2c8b592a"
        family = ""
        hash = "442c477cf373706ffe005bbd15dde5f6a8d0c11482bbcec6627c2949b67d9e70"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-2c8b592a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "            ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))" ascii
        $s1 = "        [System.Diagnostics.Process]::Start($psi) | Out-Null" ascii
        $s2 = "while (-not ([Security.Principal.WindowsPrincipal]`" ascii
        $s3 = "        $psi.Arguments       = \"-NoLogo -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File" ascii
        $s4 = "$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path" ascii
        $s5 = "    public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);" ascii
        $s6 = "            [Security.Principal.WindowsIdentity]::GetCurrent()`" ascii
        $s7 = "        $psi = New-Object System.Diagnostics.ProcessStartInfo" ascii
        $s8 = "Start-Process -FilePath $exePath -WindowStyle Hidden" ascii
        $s9 = "    public static extern IntPtr GetConsoleWindow();" ascii
        $s10 = "$hwnd = [Win32]::GetConsoleWindow()" ascii
        $s11 = "# Get the path of the folder where this script is located" ascii
    condition:
        filesize < 1048576 and 12 of them
}
