rule Sightlines_tlsh_4ca2da33_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-4ca2da33"
        date = "2026-11-05"
        campaign = "tlsh-4ca2da33"
        family = ""
        hash = "146efc37c7518eaa29be03abe2a42e9e3385f54fced06c060e3e732326a3c3cd"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-4ca2da33.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "            var fs = getCOM('Scripting.FileSystemObject');" ascii
        $s1 = "            comCache[progId] = new ActiveXObject(progId);" ascii
        $s2 = "            return Ops.fetch(config.address, config.maxAttempts);" ascii
        $s3 = "    Pipeline.prototype.add = function(name, fn) {" ascii
        $s4 = "            return Ops.execPS(payload, config.directory);" ascii
        $s5 = "    // Configuration stored as a closure variable with default factory" ascii
        $s6 = "        execPS: function(scriptBody, dir) {" ascii
        $s7 = "    // COM objects initialized lazily via getters" ascii
        $s8 = "    Pipeline.prototype.execute = function(input) {" ascii
        $s9 = "    // Namespace object to hold all utility operations" ascii
        $s10 = "        saveText: function(filePath, text) {" ascii
        $s11 = "            if (fs.FolderExists(dirPath)) return true;" ascii
    condition:
        filesize < 1048576 and 12 of them
}
