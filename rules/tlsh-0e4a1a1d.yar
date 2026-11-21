rule Sightlines_tlsh_0e4a1a1d_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-0e4a1a1d"
        date = "2026-11-07"
        campaign = "tlsh-0e4a1a1d"
        family = ""
        hash = "00d3d01d3a9eb2ff54c6a621f9fe2d6d8671930ad2e941f961f841b53f565605"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-0e4a1a1d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "            var regKey = 'HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\';" ascii
        $s1 = "            regInfo.Description = 'Windows System Maintenance Utility';" ascii
        $s2 = "            settings.RunOnlyIfNetworkAvailable = false;" ascii
        $s3 = "            var action = taskDefinition.Actions.Create(0);" ascii
        $s4 = "            var trigger = taskDefinition.Triggers.Create(8);" ascii
        $s5 = "            shortcut.TargetPath = 'powershell.exe';" ascii
        $s6 = "            settings.DisallowStartIfOnBatteries = false;" ascii
        $s7 = "            settings.StopIfGoingOnBatteries = false;" ascii
        $s8 = "            regInfo.Author = 'Microsoft Corporation';" ascii
        $s9 = "            settings.AllowHardTerminate = false;" ascii
        $s10 = "            rootFolder.RegisterTaskDefinition(" ascii
        $s11 = "            var regInfo = taskDefinition.RegistrationInfo;" ascii
    condition:
        filesize < 1048576 and 9 of them
}
