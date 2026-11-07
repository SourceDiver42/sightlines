rule Sightlines_imphash_5add887a_riseprostealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-5add887a"
        date = "2026-11-04"
        campaign = "imphash-5add887a"
        family = "riseprostealer"
        hash = "2b236b0c36b74b0cfbfccc76924624643d60c74720679b4aaa3799009b781c84"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-5add887a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "RMDir: RemoveDirectory invalid input(\"%s\")" wide
        $s1 = "File: overwriteflag=%d, allowskipfilesflag=%d, name=\"%s\"" wide
        $s2 = "ExecShell: warning: error (\"%s\": file:\"%s\" params:\"%s\")=%d" wide
        $s3 = "\\Microsoft\\Internet Explorer\\Quick Launch" wide
        $s4 = "IfFileExists: file \"%s\" does not exist, jumping %d" wide
        $s5 = "Installer integrity check has failed. Common causes include" wide
        $s6 = "IfFileExists: file \"%s\" exists, jumping %d" wide
        $s7 = "File: skipped: \"%s\" (overwriteflag=%d)" wide
        $s8 = "Error writing temporary file. Make sure your temp folder is valid." wide
        $s9 = "CreateDirectory: can't create \"%s\" (err=%d)" wide
        $s10 = "Error registering DLL: Could not initialize OLE" wide
        $s11 = "ExecShell: success (\"%s\": file:\"%s\" params:\"%s\")" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 16117248 and 12 of them
}
