rule Sightlines_imphash_955691b5_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-955691b5"
        date = "2026-11-13"
        campaign = "imphash-955691b5"
        family = ""
        hash = "0a40c9c25a29f3c5f546c139f6b030b154cce27eafab8a66981ae5c361582eb8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-955691b5.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "0225f93a}\"/><supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/><supportedOS Id=\"{1f676c76-80e" ascii
        $s1 = "1-4239-95bb-83d0f6d0da78}\"/><supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/><maxversiontes" ascii
        $s2 = "portedOS Id=\"{e2011457-1546-43c5-a5fe-008deee3d3f0}\"/><supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a244" ascii
        $s3 = "ted Id=\"10.0.18362.0\"/></application></compatibility></assembly>" ascii
        $s4 = "><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=" ascii
        $s5 = "bly></dependency><compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\"><application><sup" ascii
        $s6 = "<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecuti" ascii
        $s7 = "onLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><dependency" ascii
        $s8 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion" wide
        $s9 = "Copyright 2026 Google LLC. All rights reserved." wide
        $s10 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." ascii
        $s11 = "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 4 of them
}
