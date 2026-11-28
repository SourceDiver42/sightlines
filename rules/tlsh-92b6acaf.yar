rule Sightlines_tlsh_92b6acaf_formbook
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-92b6acaf"
        date = "2026-11-24"
        campaign = "tlsh-92b6acaf"
        family = "formbook"
        hash = "2ebec59d201e7ea2fee83a0e29a64707788cc153e86d8459a27a3ef8b29f7604"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-92b6acaf.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "            var token = Math.random().toString(36).slice(2, 10).toUpperCase();" ascii
        $s1 = "        fs: new ActiveXObject('Scripting.FileSystemObject')," ascii
        $s2 = "        var payload = network.fetchText(settings.address, settings.maxAttempts);" ascii
        $s3 = "        http: new ActiveXObject('MSXML2.XMLHTTP')" ascii
        $s4 = "            if (Object.prototype.hasOwnProperty.call(source, key)) {" ascii
        $s5 = "        return powershell.executeScript(payload, settings.directory);" ascii
        $s6 = "        shell: new ActiveXObject('WScript.Shell')," ascii
        $s7 = "    var settings = merge({}, DEFAULTS);" ascii
        $s8 = "    // ES3-safe replacement for Object.assign" ascii
        $s9 = "            if (Object.prototype.hasOwnProperty.call(target, key)) {" ascii
        $s10 = "            var filePath = targetDir + filesystem.randomScriptName();" ascii
        $s11 = "            var handle = com.fs.CreateTextFile(filePath, true);" ascii
    condition:
        filesize < 1048576 and 12 of them
}
