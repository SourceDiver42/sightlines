rule Sightlines_imphash_e9e833e0_gh0strat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-e9e833e0"
        date = "2026-11-09"
        campaign = "imphash-e9e833e0"
        family = "gh0strat"
        hash = "2352c67bb94eff5951c0a339c7437c7d88c7430e67bd00db17dd2b63ce58cba8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-e9e833e0.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "function DownloadTemporaryFile(const Url, FileName, RequiredSHA256OfFile: String; const OnDownloadPr" ascii
        $s1 = "        <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" ascii
        $s2 = "?TObjectDictionary<Winapi.Windows.HWND,Vcl.Themes.TSysStyleHook>M" ascii
        $s3 = "`TEnumerable<System.Generics.Collections.TPair<Winapi.Windows.HWND,Vcl.Themes.TChildControlInfo>>'" ascii
        $s4 = "\\TEnumerable<System.Generics.Collections.TPair<Winapi.Windows.HWND,Vcl.Themes.TSysStyleHook>>'" ascii
        $s5 = "LTDictionary<Winapi.Windows.HWND,Vcl.Themes.TChildControlInfo>.TKeyEnumerator;" ascii
        $s6 = "CTObjectDictionary<Winapi.Windows.HWND,Vcl.Themes.TChildControlInfo>M" ascii
        $s7 = "`TEnumerator<System.Generics.Collections.TPair<Winapi.Windows.HWND,Vcl.Themes.TChildControlInfo>>(" ascii
        $s8 = "ITDictionary<Winapi.Windows.HWND,Vcl.Themes.TSysStyleHook>.TPairEnumerator;" ascii
        $s9 = "\\TEnumerator<System.Generics.Collections.TPair<Winapi.Windows.HWND,Vcl.Themes.TSysStyleHook>>(" ascii
        $s10 = "JTDictionary<Winapi.Windows.HWND,Vcl.Themes.TSysStyleHook>.TValueEnumerator;" ascii
        $s11 = "Invalid time Offset string: %s$SHA2: Cannot update a finalized hash=Error decoding URL style (%%XX) " wide
    condition:
        uint16(0) == 0x5A4D and filesize < 40811752 and 12 of them
}
