rule Sightlines_imphash_744e1ae6_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-744e1ae6"
        date = "2026-11-07"
        campaign = "imphash-744e1ae6"
        family = ""
        hash = "0ce773f0c56df69c209416fd8a71708f73d7f762c12c6b60f58b86f90df550b2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-744e1ae6.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "        <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" ascii
        $s1 = "        <supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/>" ascii
        $s2 = "        <supportedOS Id=\"{e2011457-1546-43c5-a5fe-008deee3d3f0}\"/>" ascii
        $s3 = "FastMM Borland Edition (c) 2004 - 2008 Pierre le Riche / Professional Software Development" ascii
        $s4 = "<compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\">" ascii
        $s5 = "<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s6 = "%s5Could not convert variant of type (%s) into type (%s)=Overflow while converting variant of type (" wide
        $s7 = "The setup files are corrupted. Please obtain a new copy of the program." wide
        $s8 = "lzmadecompsmall: Compressed data is corrupted (%d)" wide
        $s9 = "Invalid variant operation%Invalid variant operation (%s%.8x)" wide
        $s10 = "Write$Error creating variant or safe array)Variant or safe array index out of bounds" wide
        $s11 = "Wed(Monitor support function not initialized" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 17278370 and 12 of them
}
