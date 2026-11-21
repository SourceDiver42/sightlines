rule Sightlines_imphash_e86de743_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-e86de743"
        date = "2026-11-15"
        campaign = "imphash-e86de743"
        family = ""
        hash = "034511d46150f10b0e28b571ab8972a6564b1f773d2a3431fe2518d6b5beb225"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-e86de743.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "SOFTWARE\\Wow6432Node\\Microsoft\\VisualStudio\\14.0\\Setup\\VC" wide
        $s1 = "estedExecutionLevel></requestedPrivileges></security></trustInfo></assembly>PADDINGXXPADDINGPADDINGX" ascii
        $s2 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity name=\"jab" ascii
        $s3 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Accessibility\\Session" wide
        $s4 = "3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requ" ascii
        $s5 = "The USERPROFILE environment variable is too long." ascii
        $s6 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Accessibility" wide
        $s7 = "  activated by pressing Windows + U).  The Ease of Access" ascii
        $s8 = "#assistive_technologies=com.sun.java.accessibility.AccessBridge" ascii
        $s9 = "jabswitch [/enable | /disable | /version | /?]" ascii
        $s10 = "Changing the code in this way will not affect the quality of the resulting optimized code." ascii
        $s11 = "The value of ESP was not properly saved across a function call.  This is usually a result of calling" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
