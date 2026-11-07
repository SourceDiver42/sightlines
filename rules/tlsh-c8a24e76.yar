rule Sightlines_tlsh_c8a24e76_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-c8a24e76"
        date = "2026-11-05"
        campaign = "tlsh-c8a24e76"
        family = ""
        hash = "497f188df761d422f0f96d90022ca8faf07854d73c299e6ef6fcfffd432005d5"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-c8a24e76.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "        http: function() { return new ActiveXObject('MSXML2.XMLHTTP'); }" ascii
        $s1 = "        filesystem: function() { return new ActiveXObject('Scripting.FileSystemObject'); }," ascii
        $s2 = "        shell: function() { return new ActiveXObject('WScript.Shell'); }," ascii
        $s3 = "            return Executor.runScript(state.payload, configState.get('directory'));" ascii
        $s4 = "        pipeline.addStep('fetchPayload', function(state) {" ascii
        $s5 = "            return FileOps.ensureFolder(configState.get('directory'));" ascii
        $s6 = "        pipeline.addStep('executePayload', function(state) {" ascii
        $s7 = "        // Step 3: Execute PowerShell (skipped if no payload)" ascii
        $s8 = "        pipeline.addStep('ensureDir', function(state) {" ascii
        $s9 = "    // Configuration Store (encapsulated)" ascii
        $s10 = "                FileOps.writeText(fullPath, scriptContent);" ascii
        $s11 = "            var fileName = FileOps.randomScriptName();" ascii
    condition:
        filesize < 1048576 and 12 of them
}
