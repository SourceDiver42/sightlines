rule Sightlines_signer_cert_sha1_1d87c492_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-1d87c492"
        date = "2026-11-11"
        campaign = "signer_cert_sha1-1d87c492"
        family = ""
        hash = "026a78c66f17587d94c5a83c0d0815f1f45a41b25f740e984f62d55a5ea9545c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-1d87c492.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\" />" ascii
        $s1 = "      <supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\" />" ascii
        $s2 = "      <supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\" />" ascii
        $s3 = "      <supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\" />" ascii
        $s4 = "      <supportedOS Id=\"{e2011457-1546-43c5-a5fe-008deee3d3f0}\" />" ascii
        $s5 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s6 = "<Module>{09D611C0-FB7B-E958-B628-0ADDCF2E3E7D}" ascii
        $s7 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s8 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\" />" ascii
        $s9 = "742EB14EC82FD7DCE8A8B8165C5AE7AABD3935C69B50E82F066C4890BD7C5D1F" ascii
        $s10 = "652CBA73703AE51D50D68B771557019C2C7D44D9784F036693BD7E681028AA84" ascii
        $s11 = "128605DD5EC3F87EB915E0EDA22D0F52C595C0CF7986D911ED2CA1C403FB7B83" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 22860816 and 12 of them
}
