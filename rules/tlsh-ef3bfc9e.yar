rule Sightlines_tlsh_ef3bfc9e_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-ef3bfc9e"
        date = "2026-11-12"
        campaign = "tlsh-ef3bfc9e"
        family = ""
        hash = "50569ea13be14c4774b2125ed8eb49ff77a82a95c70451b0bdd1aaaa8ab5c09b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-ef3bfc9e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "    If Not WriteFile(gPayloadPath, gHttp.ResponseText) Then Exit Function" ascii
        $s1 = "    gPayloadPath = gStageDir & RandomTag(8) & \".ps1\"" ascii
        $s2 = "Dim gUrl, gStageDir, gPayloadPath, gLaunchCmd, gFs, gShell, gHttp" ascii
        $s3 = "    gLaunchCmd = \"powershell.exe -nop -ep bypass -file \"\"\" & gPayloadPath & \"\"\"\"" ascii
        $s4 = "    If Not gFs.FolderExists(gStageDir) Then" ascii
        $s5 = "    Set gHttp = CreateObject(\"MSXML2.XMLHTTP\")" ascii
        $s6 = "    Set gFs = CreateObject(\"Scripting.FileSystemObject\")" ascii
        $s7 = "    If Not PrepWorkspace() Then Exit Function" ascii
        $s8 = "        If Not MakeFolder(gStageDir) Then Exit Function" ascii
        $s9 = "    If Not FetchPayload() Then Exit Function" ascii
        $s10 = "    Set out = gFs.CreateTextFile(path, True)" ascii
        $s11 = "    Set gShell = CreateObject(\"WScript.Shell\")" ascii
    condition:
        filesize < 1048576 and 12 of them
}
