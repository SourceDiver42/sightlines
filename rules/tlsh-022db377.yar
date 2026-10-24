rule Sightlines_tlsh_022db377_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-022db377"
        date = "2026-10-21"
        campaign = "tlsh-022db377"
        family = "mirai"
        hash = "0c0dd052789ca7513dfa96a62727b31735f219c14da0de7fea1a7216bab7bc57"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-022db377.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "cat > \"$d/network-dispatch.service\" <<EOF" ascii
        $s1 = "ln -sf \"$d/network-dispatch.service\" \"$d/multi-user.target.wants/network-dispatch.service\"" ascii
        $s2 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ascii
        $s3 = "/magisk/.core/service.d/99-network-dispatch" ascii
        $s4 = "/root/.config/systemd/user/network-dispatch.service" ascii
        $s5 = "/etc/udev/rules.d/99-network-dispatch.rules" ascii
        $s6 = "Cache-Control: no-cache, no-store, must-revalidate" ascii
        $s7 = "option post_install_hook /etc/init.d/network-dispatch" ascii
        $s8 = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s" ascii
        $s9 = "rc_startup=/etc/init.d/network-dispatch start" ascii
        $s10 = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6" ascii
        $s11 = "/etc/xdg/autostart/network-dispatch.desktop" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1111288 and 11 of them
}
