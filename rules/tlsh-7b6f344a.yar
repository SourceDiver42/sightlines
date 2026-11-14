rule Sightlines_tlsh_7b6f344a_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-7b6f344a"
        date = "2026-11-09"
        campaign = "tlsh-7b6f344a"
        family = ""
        hash = "2274cf0e7ec3e85caafec665eafab8d8508a2cd442776ff7c7837c4d0bff5e18"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-7b6f344a.json"
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
        $s11 = "MTDictionary<Winapi.Windows.HWND,Vcl.Themes.TChildControlInfo>.TPairEnumerator;" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 7204864 and 12 of them
}
