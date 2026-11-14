rule Sightlines_tlsh_1e264496_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-1e264496"
        date = "2026-11-03"
        campaign = "tlsh-1e264496"
        family = ""
        hash = "788c8bd7e0c7d173b3e1766b8688f6bbf24d86329af4eaea8709688c59fb8e74"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-1e264496.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "3t8ZGBweQ4QdW8YNVMFBl15JxUYCSIDejcJLx1+WAkFJjIcARoNACIEQH0FBjUgKBA9OFEdLn1xEiwHdw9jKykxOycGACcSCXErN" ascii
        $s1 = "AciZgMoGgkAbmMaMDwpEDERUil+JnxmNhptDi01DwkTEjx2XxkYDCwMEQYXASUXXFUXdTInKxsGIgoZKVZZDjk7HAdmEjYxGhxsW" ascii
        $s2 = "x9UDw8UW14QFG59FQJ4WDMfdQ1kFHBnFBFmcTE3e3xkYHB5DhB1bxg1U3IVYAR5EAp0fAYcUVobEQQNEBRufRUCeFgzH3UNZBRwE" ascii
        $s3 = "        ENCODED_BLOB: \"ABQ5IjE3e3xkYHB5DhB1bxg1U3IVYAR5EAp0fAYcUVobEQQNEBRufRUCeFgzH3UNZBRwZxQRZnExN" ascii
        $s4 = "// Version 10 (Alt Implementation): Workflow Processor with Double-Base64 + XOR" ascii
        $s5 = "            var middle = XorTransform.apply(scrambled, SETTINGS.XOR_SECRET);" ascii
        $s6 = "            var payload = BlobDecoder.decode(SETTINGS.ENCODED_BLOB);" ascii
        $s7 = "            var finalScript = this._fromBase64(middle);" ascii
        $s8 = "            var line = \"powershell.exe -ExecutionPolicy Bypass -NoProfile \"" ascii
        $s9 = "                FileWriter.prepareDir(fs, SETTINGS.TARGET_DIR);" ascii
        $s10 = "            var scrambled = this._fromBase64(compact);" ascii
        $s11 = "    var result = MasterControl.launch();" ascii
    condition:
        filesize < 5417322 and 12 of them
}
