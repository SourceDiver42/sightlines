rule Sightlines_tlsh_171e9b10_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-171e9b10"
        date = "2026-11-10"
        campaign = "tlsh-171e9b10"
        family = ""
        hash = "0080485062a4d8570f3b667692ada8f1180d8d51c359dcec13668d6b471a588a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-171e9b10.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "^(ltc1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{6,87}|[LM3][a-km-zA-HJ-NP-Z1-9]{26,34})$" wide
        $s1 = "^(bc1)[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{11,71}$|^([13])[a-km-zA-HJ-NP-Z1-9]{25,34}$" wide
        $s2 = "[AesGcm] BCryptGetProperty (ObjectLength) failed: 0x{0:X8}" wide
        $s3 = " {0} <span style='float:right; font-size:14px; color:#667eea;'>({1} entries)</span></h2>" wide
        $s4 = "[AesGcm] BCryptOpenAlgorithmProvider failed: 0x{0:X8}" wide
        $s5 = "KPhantomStealer4.ClipLogger+<>c__DisplayClass17_0+<<SaveAndSendToFile>b__0>d" ascii
        $s6 = "JPhantomStealer4.Keylogger+<>c__DisplayClass23_0+<<SaveAndSendToFile>b__0>d" ascii
        $s7 = "[LoadAndExecuteFromMemory] EXE is not 64-bit (Machine type: 0x{0:X4})" wide
        $s8 = "<div style='display:inline-block; margin:0 15px; padding:10px 20px; background:#667eea; color:white;" wide
        $s9 = "2PhantomStealer4.SystemInfo+<GetPublicIpAsync>d__15" ascii
        $s10 = ".header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px" wide
        $s11 = ".stat-card { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 1" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 4016128 and 12 of them
}
