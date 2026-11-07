rule Sightlines_tlsh_aff3077f_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-aff3077f"
        date = "2026-11-05"
        campaign = "tlsh-aff3077f"
        family = ""
        hash = "3a117682675e884828650c15a83a6c05af1848ae1e3928fcf90fd1c2a7ec68a5"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-aff3077f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "[MAINTENANCE] Compressed air blown through pallet chest. Dust and grit removed." wide
        $s1 = "[STOKE] Engineer shoveled anthracite coal into steam boiler firebox (+15 PSI)." wide
        $s2 = "[FAULT] Dirty pallet valve sticking! Cipher note sounding on rank {0}." wide
        $s3 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s4 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s5 = "Heavy Chord Drop: {0:F1} mm WG (Current: {1:F0})" wide
        $s6 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s7 = "[REPAIR] Book binder applied gummed linen tape across paper fold hinge." wide
        $s8 = "Book Folds: {0:F0}% integrity ({1} fold tears)" wide
        $s9 = "Governor Drift: {0:F1} RPM (Speed: {1:F0} RPM)" wide
        $s10 = "<FairgroundOrgans.OrganForm.IChannelSource.Produce>b__0" ascii
        $s11 = "[WEAR] Cardboard fold fatigue tear detected in '{0}'." wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1879040 and 12 of them
}
