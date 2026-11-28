rule Sightlines_tlsh_fe086d7a_winosstager
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-fe086d7a"
        date = "2026-11-04"
        campaign = "tlsh-fe086d7a"
        family = "winosstager"
        hash = "4421ccd153aa864e3eb4ac89044c92eba48a1ecca7efc759203368004a7ded05"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-fe086d7a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "AMicrosoft Visual C++ Runtime Library" wide
        $s1 = ".?AV?$CArqSessionT@VCUdpSocket@@V1@@@" ascii
        $s2 = "</assembly>PAPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPAD" ascii
        $s3 = "input ack: sn=%lu rtt=%ld rto=%ld" ascii
        $s4 = "Windows\\SysWOW64\\tracerpt.exe" ascii
        $s5 = "Windows\\System32\\tracerpt.exe" ascii
        $s6 = "%s-%04d%02d%02d-%02d%02d%02d.dmp" wide
        $s7 = "input psh: sn=%lu ts=%lu" ascii
        $s8 = ".?AVCKernelManager@@" ascii
        $s9 = ".?AVISocketBase@@" ascii
        $s10 = ".?AVCUdpSocket@@" ascii
        $s11 = ".?AVCTcpSocket@@" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
