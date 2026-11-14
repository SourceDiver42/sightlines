rule Sightlines_tlsh_d5bf989e_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-d5bf989e"
        date = "2026-11-03"
        campaign = "tlsh-d5bf989e"
        family = ""
        hash = "3b0730216680a69c14daed9cb76a78115b9747cd0065e3482b69a0f3039824d8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-d5bf989e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "WALLET=\"87LCpiz8fP2MYH3dnd9SzbTcpR8og1p9kYxsQrNucbYkWBF7ryY3tfwRNFUFVFyhP3NydQ2iZSaScQym3q3j9hSiHTaD" ascii
        $s1 = "URL=\"https://github.com/xmrig/xmrig/releases/download/${TAG}/${ASSET}\"" ascii
        $s2 = "JSON=$(curl -fsSL https://api.github.com/repos/xmrig/xmrig/releases/latest 2>/dev/null)" ascii
        $s3 = "    x86_64)  ASSET=\"xmrig-${VER}-linux-static-x64.tar.gz\" ;;" ascii
        $s4 = "    aarch64) ASSET=$(echo \"$JSON\" | grep browser_download_url | grep -i \"arm64\\|aarch64\" | grep \"\\.t" ascii
        $s5 = "    mkdir -p \"${DIR}/.config/systemd/user\" 2>/dev/null" ascii
        $s6 = "    export XDG_RUNTIME_DIR=\"${XDG_RUNTIME_DIR:-/run/user/${UID_N}}\"" ascii
        $s7 = "        ENTRY=\"@reboot XDG_RUNTIME_DIR=${XDG_RUNTIME_DIR} $BIN --config $CFG \"" ascii
        $s8 = "XDIR=$(find \"$TMP\" -maxdepth 1 -type d -name \"xmrig-*\" | head -1)" ascii
        $s9 = "$SC enable xmrig.service 2>/dev/null && L \"service enabled (auto-start on boot)\"" ascii
        $s10 = "install -m 755 \"$XDIR/xmrig\" \"$BIN\" && L \"binary installed: $BIN\"" ascii
        $s11 = "    sysctl -w vm.nr_hugepages=1280 2>/dev/null && L \"hugepages set\"" ascii
    condition:
        filesize < 1048576 and 12 of them
}
