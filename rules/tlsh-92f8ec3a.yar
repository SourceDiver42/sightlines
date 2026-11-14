rule Sightlines_tlsh_92f8ec3a_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-92f8ec3a"
        date = "2026-11-03"
        campaign = "tlsh-92f8ec3a"
        family = ""
        hash = "0c94d77776c08b660932586745e3e5c65c6754217c992e62a0a7e8a90f9b7fd9"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-92f8ec3a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "    // ---- State container (single mutable object instead of closure-scoped config) ----" ascii
        $s1 = "    // ---- Orchestrator: sequential gate checks (same order, same short-circuits) ----" ascii
        $s2 = "        return persistAndLaunch(payload);" ascii
        $s3 = "    function persistAndLaunch(script) {" ascii
        $s4 = "            var handle = fs.CreateTextFile(target, true);" ascii
        $s5 = "    // ---- Step helpers, each returns boolean or payload ----" ascii
        $s6 = "        // filename via reverse-built random token" ascii
        $s7 = "        // do/while loop instead of for-with-index" ascii
        $s8 = "            // short-circuit: stop as soon as we have content" ascii
        $s9 = "        var triesLeft = State.retries;" ascii
        $s10 = "    function fetchPayload() {" ascii
        $s11 = "    function ensureFolder() {" ascii
    condition:
        filesize < 1048576 and 12 of them
}
