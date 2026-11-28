rule Sightlines_tlsh_8386281e_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-8386281e"
        date = "2026-11-24"
        campaign = "tlsh-8386281e"
        family = ""
        hash = "353b8698a2ea6305af718ab8729308f0e8d3d23d6c7221c55a1072ac011b6ea9"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-8386281e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "    var httpClient = new ActiveXObject('MSXML2.XMLHTTP');" ascii
        $s1 = "        var randomChunk = Math.random().toString(36).slice(2, 10);" ascii
        $s2 = "    var fileSystem = new ActiveXObject('Scripting.FileSystemObject');" ascii
        $s3 = "            if (Object.prototype.hasOwnProperty.call(settings, key) && value !== undefined) {" ascii
        $s4 = "    var shell = new ActiveXObject('WScript.Shell');" ascii
        $s5 = "    function executePowerShellScript(scriptBody, destinationFolder) {" ascii
        $s6 = "        return executePowerShellScript(payload, settings.directory);" ascii
        $s7 = "            if (Object.prototype.hasOwnProperty.call(settings, key)) {" ascii
        $s8 = "        var payload = downloadText(settings.address, settings.maxAttempts);" ascii
        $s9 = "    function downloadText(targetUrl, retryCount) {" ascii
        $s10 = "    function saveTextToFile(fullPath, text) {" ascii
        $s11 = "            saveTextToFile(fullPath, scriptBody);" ascii
    condition:
        filesize < 1048576 and 12 of them
}
