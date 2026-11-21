rule Sightlines_tlsh_a2ba1ff5_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a2ba1ff5"
        date = "2026-11-19"
        campaign = "tlsh-a2ba1ff5"
        family = ""
        hash = "17bcfccaff1a9aee3dfdc17e38ee5017d6a88e39594c1ec0859e18d5e259c6af"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a2ba1ff5.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "    if command -v busybox >/dev/null 2>&1; then" ascii
        $s1 = "    if command -v lwp-download >/dev/null 2>&1; then" ascii
        $s2 = "    if command -v ftpget >/dev/null 2>&1; then" ascii
        $s3 = "    if command -v wget >/dev/null 2>&1; then" ascii
        $s4 = "    if command -v curl >/dev/null 2>&1; then" ascii
        $s5 = "    if command -v tftp >/dev/null 2>&1; then" ascii
        $s6 = "    _endpoints=$(select_endpoints) || return 1" ascii
        $s7 = "            printf '%s\\n' /bot_mips64 /bots_mips64le /bot_mips64le" ascii
        $s8 = "            printf '%s\\n' /bots_mips64le /bot_mips64 /bot_mips64le" ascii
        $s9 = "    trap '_cleanup' EXIT HUP INT TERM" ascii
        $s10 = "for d in /tmp /var/tmp /var/run /dev/shm /mnt /root /; do" ascii
        $s11 = "    for _ep in $_endpoints; do" ascii
    condition:
        filesize < 1048576 and 12 of them
}
