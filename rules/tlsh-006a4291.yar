rule Sightlines_tlsh_006a4291_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-006a4291"
        date = "2026-11-03"
        campaign = "tlsh-006a4291"
        family = ""
        hash = "7037122b847bc1c67837856a968454f4bac25a51fc9d3cafcfd5e1cc217b95a4"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-006a4291.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "<ModifyWindowsInstaller>g__InsertClientLaunchParameterIfNotEmpty|0" ascii
        $s1 = "<System-Collections-IEnumerable-GetEnumerator>d__27" ascii
        $s2 = "<GetAllSignedDataNodesOrderedOutermostFirst>b__0_1" ascii
        $s3 = "<GetAllSignedDataNodesOrderedOutermostFirst>b__0_2" ascii
        $s4 = "<GetAllSignedDataNodesOrderedOutermostFirst>b__0_3" ascii
        $s5 = "<GetAllSignedDataNodesOrderedOutermostFirst>b__0_4" ascii
        $s6 = "<GetAllSignedDataNodesOrderedOutermostFirst>b__0_5" ascii
        $s7 = "Unsupported Binary File Format version: OpenMcdf only supports Compound Files with major version equ" wide
        $s8 = "C:\\builds\\cc\\cwcontrol\\Product\\WindowsInstaller\\obj\\Release\\net20\\ScreenConnect.WindowsInstaller.pdb" ascii
        $s9 = "<GetAllSignedDataNodesOrderedOutermostFirst>b__0_0" ascii
        $s10 = ".Use flag LeaveOpen in CompoundFile constructor" ascii
        $s11 = "System.IComparable<ScreenConnect.OpenMcdf.CFItem>.CompareTo" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
