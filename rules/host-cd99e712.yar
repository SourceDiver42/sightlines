rule Sightlines_host_cd99e712_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign host-cd99e712"
        date = "2026-11-14"
        campaign = "host-cd99e712"
        family = ""
        hash = "13db09fa002edc7e376a55fcc9aa0ae1897beaaada29875bb11f0056a4a69a92"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/host-cd99e712.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}" ascii
        $s1 = "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0" ascii
        $s2 = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\" ascii
        $s3 = "SOFTWARE\\Oracle\\VirtualBox Guest Additions" ascii
        $s4 = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0" ascii
        $s5 = "SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters" ascii
        $s6 = "https://steamcommunity.com/profiles/76561198610252751" ascii
        $s7 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" ascii
        $s8 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" wide
        $s9 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall" ascii
        $s10 = "Content-Type: multipart/form-data; boundary=----%s" ascii
        $s11 = "Content-Disposition: form-data; name=\"build_id\"" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1875968 and 3 of them
}
