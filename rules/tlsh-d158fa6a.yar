rule Sightlines_tlsh_d158fa6a_formbook
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-d158fa6a"
        date = "2026-11-09"
        campaign = "tlsh-d158fa6a"
        family = "formbook"
        hash = "29bee5672bc389151d94beca82fcae697ad066697405cb8a437208672fdd637d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-d158fa6a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "3t8ZWFweQ4FZ3gYNVMFBlx4JxUYHDAUejcJLx1/WQkFJicOFhoNACIEQXwFBhgELgMNOzQFPFBtAnA/Bm40ASQ1Ph8HWTUaDRA4J" ascii
        $s1 = "SIsEw8UWl8QFG5oBxV4WDMfdQxlFHBnAQNxcTE3e3xlYXB5DgVneBg1U3IVYQV5EAphbhEcUVobEQUMEBRuaAcVeFgzH3UMZRRwE" ascii
        $s2 = "        ENCODED_BLOB: \"FQYuIjE3e3xlYXB5DgVneBg1U3IVYQV5EAphbhEcUVobEQUMEBRuaAcVeFgzH3UMZRRwZwEDcXExN" ascii
        $s3 = "// Version 10 (Alt Implementation): Workflow Processor with Double-Base64 + XOR" ascii
        $s4 = "            var middle = XorTransform.apply(scrambled, SETTINGS.XOR_SECRET);" ascii
        $s5 = "            var payload = BlobDecoder.decode(SETTINGS.ENCODED_BLOB);" ascii
        $s6 = "            var finalScript = this._fromBase64(middle);" ascii
        $s7 = "            var line = \"powershell.exe -ExecutionPolicy Bypass -NoProfile \"" ascii
        $s8 = "                FileWriter.prepareDir(fs, SETTINGS.TARGET_DIR);" ascii
        $s9 = "            var scrambled = this._fromBase64(compact);" ascii
        $s10 = "    var result = MasterControl.launch();" ascii
        $s11 = "// Save as: wsh_processor_alt_v9.js" ascii
    condition:
        filesize < 5580026 and 12 of them
}
