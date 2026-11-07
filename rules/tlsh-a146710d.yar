rule Sightlines_tlsh_a146710d_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a146710d"
        date = "2026-11-02"
        campaign = "tlsh-a146710d"
        family = ""
        hash = "69c31bb1ccb62dc616eaacd7dfca34913070d98cb2075239fabe809bddd01439"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a146710d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" ascii
        $s1 = "The result is too small to be represented (UNDERFLOW)" ascii
        $s2 = "      <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" ascii
        $s3 = "random_device::random_device(const std::string&): unsupported token" ascii
        $s4 = "random_device::random_device(const std::string&): device not available" ascii
        $s5 = "cannot create std::vector larger than max_size()" ascii
        $s6 = "basic_string::_M_construct null not valid" ascii
        $s7 = "basic_string::_S_construct null not valid" ascii
        $s8 = "std::basic_string<char, std::char_traits<char>, std::allocator<char> >" ascii
        $s9 = "std::basic_iostream<char, std::char_traits<char> >" ascii
        $s10 = "std::basic_ostream<char, std::char_traits<char> >" ascii
        $s11 = "std::basic_istream<char, std::char_traits<char> >" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1190912 and 12 of them
}
