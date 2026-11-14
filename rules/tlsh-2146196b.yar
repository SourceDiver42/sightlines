rule Sightlines_tlsh_2146196b_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-2146196b"
        date = "2026-11-10"
        campaign = "tlsh-2146196b"
        family = ""
        hash = "046c40377beff7fd4fabc34c7ced4ecf3a11a95cdb688e2f6ebc0bc315934ac2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-2146196b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "<Module>{09D611C0-FB7B-E958-B628-0ADDCF2E3E7D}" ascii
        $s1 = "This assembly is protected by an unregistered version of Eziriz's \".NET Reactor\"! This assembly won'" wide
        $s2 = "VB$StateMachine_4_TryCreateFileAtomicallyAsync" ascii
        $s3 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" ascii
        $s4 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator" ascii
        $s5 = "742EB14EC82FD7DCE8A8B8165C5AE7AABD3935C69B50E82F066C4890BD7C5D1F" ascii
        $s6 = "128605DD5EC3F87EB915E0EDA22D0F52C595C0CF7986D911ED2CA1C403FB7B83" ascii
        $s7 = "F1C3EBE78BD8C38559BF3CFCC9A9FA37D221E31780774A3787E26160A61F5348" ascii
        $s8 = "C356AFF1A01C2B0DA472E584C8E3C8F875B9A24280435D42836A77B19F5A8C18" ascii
        $s9 = "97E613E5A3A47DEC76B7E50D47644B35EA4322F00D594D80D2F1C1F3644F8A4A" ascii
        $s10 = "03DCEB56B5842C722DE2821DA9906CD70AB73267EAB1A3947BFD894D19372BC7" ascii
        $s11 = "D5B7247C497788CF0031CEB06E3DF77A45FEF59F1E49633DC7159816D64759B5" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
