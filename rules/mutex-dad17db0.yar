rule Sightlines_mutex_dad17db0_coinminer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign mutex-dad17db0"
        date = "2026-11-20"
        campaign = "mutex-dad17db0"
        family = "coinminer"
        hash = "ab6d56fbb84f2a0ec4907c4ce75c5d5d79181c5a4a5554e5054460f826818bf2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/mutex-dad17db0.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "        <asmv3:windowsSettings xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\"> " ascii
        $s1 = "          <supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\" /> " ascii
        $s2 = "          <supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\" /> " ascii
        $s3 = "          <supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\" /> " ascii
        $s4 = "          <supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\" /> " ascii
        $s5 = "          <supportedOS Id=\"{e2011457-1546-43c5-a5fe-008deee3d3f0}\" /> " ascii
        $s6 = "      <compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\"> " ascii
        $s7 = "      <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"> " ascii
        $s8 = "xmlns:asmv3=\"urn:schemas-microsoft-com:asm.v3\"> " ascii
        $s9 = "xmlns=\"urn:schemas-microsoft-com:asm.v1\"  " ascii
        $s10 = "        </asmv3:windowsSettings> " ascii
        $s11 = "            <requestedExecutionLevel " ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
