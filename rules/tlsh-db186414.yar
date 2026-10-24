rule Sightlines_tlsh_db186414_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-db186414"
        date = "2026-10-22"
        campaign = "tlsh-db186414"
        family = ""
        hash = "04579a2339198dc8ffc099f59eb6727a1b0889e2916131a3de80defada9d847c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-db186414.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "[ -s q ] || { command -v python3 >/dev/null 2>&1 && python3 -c \"import urllib.request as u,sys;u.url" ascii
        $s1 = "retrieve(sys.argv[1],sys.argv[2])\" \"$U\" q 2>/dev/null; }" ascii
        $s2 = "if command -v wget >/dev/null 2>&1; then wget -q -O q \"$U\" 2>/dev/null; fi" ascii
        $s3 = "# apex4 loader - arch-detect, multi-method download, run apex4 bot (C2 31)." ascii
        $s4 = "cd /tmp 2>/dev/null || cd /dev/shm 2>/dev/null || cd /var/tmp 2>/dev/null || cd /var/run 2>/dev/null" ascii
        $s5 = "  aarch64|arm64|armv8*) A=aarch64 ;;" ascii
        $s6 = "  i386|i486|i586|i686) A=x86 ;;" ascii
        $s7 = "  ppc*|powerpc*) A=powerpc ;;" ascii
        $s8 = "chmod 777 q 2>/dev/null" ascii
        $s9 = "  mipsel) A=mipsel ;;" ascii
    condition:
        filesize < 1048576 and 9 of them
}
