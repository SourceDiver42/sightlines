rule Sightlines_tlsh_659c7d60_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-659c7d60"
        date = "2026-11-02"
        campaign = "tlsh-659c7d60"
        family = ""
        hash = "0029faf43d16de89253c90978a9ed56e8d80206a1395266e863d12d0ece83bac"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-659c7d60.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName='explorer.exe'" wide
        $s1 = "SELECT * FROM __FilterToConsumerBinding WHERE Filter LIKE '%\"" wide
        $s2 = "SELECT * FROM CommandLineEventConsumer WHERE Name='" wide
        $s3 = "SELECT * FROM __EventFilter WHERE Name='" wide
        $s4 = "payload launch: ElevatedGhostedHollowingSelfDonor backend" wide
        $s5 = "WaitForSingleObject failed for launched payload, wait=" wide
        $s6 = "SELECT * FROM __TimerEvent WHERE TimerID='" wide
        $s7 = "\\\\.\\root\\subscription:__EventFilter.Name=\"" wide
        $s8 = "payload launch: GhostedHollowingSelfDonor backend" wide
        $s9 = "ElevatedGhostedHollowingSelfDonor post-resume probe: observed=" wide
        $s10 = "RS42 launch path did not complete; trying next fallback" wide
        $s11 = "GhostedHollowingLaunchPayloadElevatedSelfDonor returned failure" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
