rule Sightlines_imphash_4fe2e768_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-4fe2e768"
        date = "2026-11-23"
        campaign = "imphash-4fe2e768"
        family = ""
        hash = "28a82071ff9eaf288b1a1f927f83c82707d712592a9fedd89b030190617a38c8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-4fe2e768.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "Post-decryption SHA-256 / SHA-512 integrity mismatch." wide
        $s2 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s3 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s4 = "Invalid DOS/NT PE headers in decrypted payload." wide
        $s5 = "AppDomain.Load failed on decrypted .NET assembly" wide
        $s6 = "The result is too small to be represented (UNDERFLOW)" ascii
        $s7 = "l.NET Framework runtime (mscoree.dll) is not available." wide
        $s8 = "Section virtual span exceeds SizeOfImage." wide
        $s9 = "Failed to initialize .NET Framework CLR host." wide
        $s10 = "Architecture mismatch: x86 stub cannot map non-x86 native binary." wide
        $s11 = "Decrypted buffer is not a valid PE image." wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 10 of them
}
