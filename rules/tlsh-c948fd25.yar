rule Sightlines_tlsh_c948fd25_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-c948fd25"
        date = "2026-11-08"
        campaign = "tlsh-c948fd25"
        family = ""
        hash = "1e2cda6006e52679151db69e7b94e99cca69298eb3bb434b7d736bea24ff5017"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-c948fd25.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "   Our application is safe to use. This message appears only because it's not EV-signed." ascii
        $s1 = "   EV certificates can only be obtained by registered companies through a paid verification process." ascii
        $s2 = "   After launching the installer, you may see a Windows SmartScreen message saying " ascii
        $s3 = "   This appears because our software is not signed with an EV code-signing certificate, which causes" ascii
        $s4 = "   As we are a small, non-profit development team creating free software, we are currently unable to" ascii
        $s5 = "   certificate or register a company solely for this purpose." ascii
        $s6 = "Windows protected your PC" ascii
        $s7 = "   classify it as an " ascii
        $s8 = "unrecognized app" ascii
        $s9 = " Windows to " ascii
        $s10 = " get this " ascii
    condition:
        filesize < 1048576 and 11 of them
}
