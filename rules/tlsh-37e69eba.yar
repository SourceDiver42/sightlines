rule Sightlines_tlsh_37e69eba_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-37e69eba"
        date = "2026-11-13"
        campaign = "tlsh-37e69eba"
        family = ""
        hash = "11d45353da749c175b3f31d1ddc0480d83196d5115323da829ae4e693b287380"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-37e69eba.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "<ModifyWindowsInstaller>g__InsertClientLaunchParameterIfNotEmpty|0" ascii
        $s1 = "WindowsNative.SizeofResource(handle, resourceInformationBlockPtr)" wide
        $s2 = "WindowsNative.LoadResource(handle, resourceInformationBlockPtr)" wide
        $s3 = "<RequireApprovalFromUserIfFileMateriallyRenamed>b__0" ascii
        $s4 = "<System-Collections-IEnumerable-GetEnumerator>d__27" ascii
        $s5 = "WindowsNative.FindResource(handle, WindowsInstallerConstants.CustomPayloadResourceName, WindowsInsta" wide
        $s6 = "<GetAllSignedDataNodesOrderedOutermostFirst>b__0_3" ascii
        $s7 = "<GetAllSignedDataNodesOrderedOutermostFirst>b__0_4" ascii
        $s8 = "<GetAllSignedDataNodesOrderedOutermostFirst>b__0_1" ascii
        $s9 = "<GetAllSignedDataNodesOrderedOutermostFirst>b__0_2" ascii
        $s10 = "<GetAllSignedDataNodesOrderedOutermostFirst>b__0_5" ascii
        $s11 = "Unsupported Binary File Format version: OpenMcdf only supports Compound Files with major version equ" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
