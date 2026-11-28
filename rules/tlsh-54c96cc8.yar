rule Sightlines_tlsh_54c96cc8_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-54c96cc8"
        date = "2026-11-27"
        campaign = "tlsh-54c96cc8"
        family = ""
        hash = "01f88961547a6afadc16dc66dc3d1e4444030c7f7e85244153d5bd3e7ce6a440"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-54c96cc8.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "            fs: new ActiveXObject('Scripting.FileSystemObject')," ascii
        $s1 = "            http: new ActiveXObject('MSXML2.XMLHTTP')" ascii
        $s2 = "            shell: new ActiveXObject('WScript.Shell')," ascii
        $s3 = "    this.ScriptAPI = api;" ascii
    condition:
        filesize < 1048576 and 4 of them
}
