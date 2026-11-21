rule Sightlines_tlsh_ed0f2f5a_purerat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-ed0f2f5a"
        date = "2026-11-04"
        campaign = "tlsh-ed0f2f5a"
        family = "purerat"
        hash = "16e6c761b64c6b330a4312ee4b7d90b17e0ba905847f4039f60c5f41897f240f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-ed0f2f5a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s3 = "742EB14EC82FD7DCE8A8B8165C5AE7AABD3935C69B50E82F066C4890BD7C5D1F" ascii
        $s4 = "128605DD5EC3F87EB915E0EDA22D0F52C595C0CF7986D911ED2CA1C403FB7B83" ascii
        $s5 = "F1C3EBE78BD8C38559BF3CFCC9A9FA37D221E31780774A3787E26160A61F5348" ascii
        $s6 = "C356AFF1A01C2B0DA472E584C8E3C8F875B9A24280435D42836A77B19F5A8C18" ascii
        $s7 = "97E613E5A3A47DEC76B7E50D47644B35EA4322F00D594D80D2F1C1F3644F8A4A" ascii
        $s8 = "03DCEB56B5842C722DE2821DA9906CD70AB73267EAB1A3947BFD894D19372BC7" ascii
        $s9 = "D5B7247C497788CF0031CEB06E3DF77A45FEF59F1E49633DC7159816D64759B5" ascii
        $s10 = "C61B1941CF756EB7551F7C661743802362728B785ADC22E860D269713DFB01A6" ascii
        $s11 = "59058FDDE6089BCA6236FD2AE2D98B3ABB38A7BC80D8DD4C75CEFD7A5D247074" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
