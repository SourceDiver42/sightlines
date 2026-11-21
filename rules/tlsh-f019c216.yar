rule Sightlines_tlsh_f019c216_winosstager
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f019c216"
        date = "2026-11-14"
        campaign = "tlsh-f019c216"
        family = "winosstager"
        hash = "05ac084e6dccde5b2d3a76a3bfa195b1cb9266d15a7408af48ba31f3c081cb36"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-f019c216.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = ".?AV?$CArqSessionT@VCUdpSocket@@V1@@@" ascii
        $s1 = "</assembly>PAPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPAD" ascii
        $s2 = "input ack: sn=%lu rtt=%ld rto=%ld" ascii
        $s3 = "Windows\\System32\\tracerpt.exe" ascii
        $s4 = "input psh: sn=%lu ts=%lu" ascii
        $s5 = ".?AVCKernelManager@@" ascii
        $s6 = ".?AVISocketBase@@" ascii
        $s7 = ".?AVCUdpSocket@@" ascii
        $s8 = ".?AVCTcpSocket@@" ascii
        $s9 = "[RO] %ld bytes" ascii
        $s10 = "input wins: %lu" ascii
        $s11 = ".?AVCManager@@" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 10 of them
}
