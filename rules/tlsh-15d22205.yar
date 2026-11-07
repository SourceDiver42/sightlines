rule Sightlines_tlsh_15d22205_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-15d22205"
        date = "2026-11-03"
        campaign = "tlsh-15d22205"
        family = ""
        hash = "0d9e9a6ba0d319b8efb05faca954515fd4e6fff56c6929906ec925026882ac53"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-15d22205.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "        <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" ascii
        $s1 = "        <supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/>" ascii
        $s2 = "        <supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/>" ascii
        $s3 = "        <supportedOS Id=\"{e2011457-1546-43c5-a5fe-008deee3d3f0}\"/>" ascii
        $s4 = "For more detailed information, please visit http://www.jrsoftware.org/ishelp/index.php?topic=setupcm" ascii
        $s5 = "<compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\">" ascii
        $s6 = "/MERGETASKS=\"comma separated list of task names\"" ascii
        $s7 = "/COMPONENTS=\"comma separated list of component names\"" ascii
        $s8 = "<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s9 = "Same as /LOG, except it allows you to specify a fixed path/filename to use for the log file." ascii
        $s10 = "/TASKS=\"comma separated list of task names\"" ascii
        $s11 = "Disables the This will install... Do you wish to continue? prompt at the beginning of Setup." ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
