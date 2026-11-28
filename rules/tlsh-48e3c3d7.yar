rule Sightlines_tlsh_48e3c3d7_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-48e3c3d7"
        date = "2026-11-13"
        campaign = "tlsh-48e3c3d7"
        family = ""
        hash = "ae096b1cd7b5e982d2becfb20e03bc1bea2ea7d95e7802e4cd4c4b52df0444b5"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-48e3c3d7.json"
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
        $s9 = "The result is too small to be represented (UNDERFLOW)" ascii
        $s10 = "Copyright 2026 Google LLC. All rights reserved." wide
        $s11 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
