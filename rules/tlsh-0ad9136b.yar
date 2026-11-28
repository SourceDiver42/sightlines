rule Sightlines_tlsh_0ad9136b_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-0ad9136b"
        date = "2026-11-26"
        campaign = "tlsh-0ad9136b"
        family = ""
        hash = "05eb597386b89a988ae483186e260daad23f0214a2d7e19d690177cf4bf80ed3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-0ad9136b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "        If Not SaveFile(mPayloadPath, mHttp.ResponseText) Then Exit Function" ascii
        $s1 = "If Not pipeline.Run(gUrl, gStageDir) Then" ascii
        $s2 = "Dim gUrl, gStageDir, gPayloadPath, gLaunchCmd" ascii
        $s3 = "        Set mFs = CreateObject(\"Scripting.FileSystemObject\")" ascii
        $s4 = "        Set mHttp = CreateObject(\"MSXML2.XMLHTTP\")" ascii
        $s5 = "        If Not mFs.FolderExists(stageDir) Then" ascii
        $s6 = "        If Not Prepare(stageDir) Then Exit Function" ascii
        $s7 = "    Private Function SaveFile(path, contents)" ascii
        $s8 = "            If Not CreateFolder(stageDir) Then Exit Function" ascii
        $s9 = "        Set mShell = CreateObject(\"WScript.Shell\")" ascii
        $s10 = "    Private Function CreateFolder(path)" ascii
        $s11 = "        Set out = mFs.CreateTextFile(path, True)" ascii
    condition:
        filesize < 1048576 and 12 of them
}
