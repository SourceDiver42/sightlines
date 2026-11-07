rule Sightlines_tlsh_cbbcd2e7_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-cbbcd2e7"
        date = "2026-11-04"
        campaign = "tlsh-cbbcd2e7"
        family = ""
        hash = "46823e07b603b7aab9e09f8ff8959297285730c340a8eae5304bac040dda15a4"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-cbbcd2e7.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Copyright (c) 1992-2004 by P.J. Plauger, licensed by Dinkumware, Ltd. ALL RIGHTS RESERVED." ascii
        $s1 = ".?AV?$CArqSessionT@VCUdpSocket@@V1@@@" ascii
        $s2 = "</assembly>PAPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPAD" ascii
        $s3 = ".?AV_Iostream_error_category@std@@" ascii
        $s4 = "input ack: sn=%lu rtt=%ld rto=%ld" ascii
        $s5 = "CreateToolhelp32Snapshot Error!" ascii
        $s6 = "Windows\\System32\\svchost.exe" ascii
        $s7 = "\\DisplaySessionContainers.log" wide
        $s8 = "ZwQueryInformationProcess" ascii
        $s9 = "ZwQuerySystemInformation" ascii
        $s10 = ".?AVGdiplusBase@Gdiplus@@" ascii
        $s11 = "GetProcessImageFileNameW" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
