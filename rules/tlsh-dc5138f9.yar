rule Sightlines_tlsh_dc5138f9_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-dc5138f9"
        date = "2026-11-11"
        campaign = "tlsh-dc5138f9"
        family = ""
        hash = "01b5938d7417c45345150d376aacbf2653aed8b5ace9e63380abf49a16af7686"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-dc5138f9.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "QkMvUEtDUzcpDQojICAgICAgICAgIC0+IEdaaXAgLT4gU2NyaXB0QmxvY2sNCiMgICBJbnRlZ3JpdHk6IFNIQS0yNTYgb2YgcGxh" ascii
        $s1 = "dXJlIExvYWRlciAtIExheWVyZWQgRW5naW5lICh2MikNCiMgICBCYXNlNjQgLT4gKFBCS0RGMi1TSEEyNTYgLT4gQUVTLTI1Ni1D" ascii
        $s2 = "PT09PQ0KU2V0LVN0cmljdE1vZGUgLVZlcnNpb24gTGF0ZXN0DQokRXJyb3JBY3Rpb25QcmVmZXJlbmNlID0gJ1N0b3AnDQoNCiRC" ascii
        $s3 = "    If Not g_fileSystem.FolderExists(WORK_DIR) Then" ascii
        $s4 = "    g_scriptPath = WORK_DIR & GenerateTag() & SCRIPT_EXT" ascii
        $s5 = "Const PS_LAUNCH = \"powershell.exe -nop -ep bypass -file \"\"\"" ascii
        $s6 = "Dim g_payloadB64, g_scriptPath, g_runCmd" ascii
        $s7 = "    If g_fileSystem.FileExists(g_scriptPath) Then g_fileSystem.DeleteFile g_scriptPath, True" ascii
        $s8 = "    Set xmlDoc = CreateObject(\"MSXML2.DOMDocument\")" ascii
        $s9 = "    Set outputFile = g_fileSystem.CreateTextFile(g_scriptPath, True)" ascii
        $s10 = "Set g_fileSystem = CreateObject(\"Scripting.FileSystemObject\")" ascii
        $s11 = "If g_success = False Then WScript.Quit 1" ascii
    condition:
        filesize < 1650466 and 12 of them
}
