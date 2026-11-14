rule Sightlines_imphash_9bc13134_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-9bc13134"
        date = "2026-10-30"
        campaign = "imphash-9bc13134"
        family = ""
        hash = "81efe7782028f005936429d2d1020ff6849086ea05f6d2872a012599e3d025e0"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-9bc13134.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = ".?AV?$CArqSessionT@VCUdpSocket@@V1@@@" ascii
        $s1 = "</assembly>PAPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPAD" ascii
        $s2 = "input ack: sn=%lu rtt=%ld rto=%ld" ascii
        $s3 = "Windows\\System32\\tracerpt.exe" ascii
        $s4 = "d33f351a4aeea5e608853d1a56661059" wide
        $s5 = "zidingyixiugaidaochuhanshu" ascii
        $s6 = "input psh: sn=%lu ts=%lu" ascii
        $s7 = ".?AVCKernelManager@@" ascii
        $s8 = ".?AVISocketBase@@" ascii
        $s9 = ".?AVCUdpSocket@@" ascii
        $s10 = ".?AVCTcpSocket@@" ascii
        $s11 = "[RO] %ld bytes" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
