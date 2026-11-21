rule Sightlines_tlsh_7b6f344a_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-7b6f344a"
        date = "2026-11-20"
        campaign = "tlsh-7b6f344a"
        family = ""
        hash = "2274cf0e7ec3e85caafec665eafab8d8508a2cd442776ff7c7837c4d0bff5e18"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-7b6f344a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "        <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" ascii
        $s1 = "?TObjectDictionary<Winapi.Windows.HWND,Vcl.Themes.TSysStyleHook>M" ascii
        $s2 = "`TEnumerable<System.Generics.Collections.TPair<Winapi.Windows.HWND,Vcl.Themes.TChildControlInfo>>'" ascii
        $s3 = "\\TEnumerable<System.Generics.Collections.TPair<Winapi.Windows.HWND,Vcl.Themes.TSysStyleHook>>'" ascii
        $s4 = "LTDictionary<Winapi.Windows.HWND,Vcl.Themes.TChildControlInfo>.TKeyEnumerator;" ascii
        $s5 = "CTObjectDictionary<Winapi.Windows.HWND,Vcl.Themes.TChildControlInfo>M" ascii
        $s6 = "`TEnumerator<System.Generics.Collections.TPair<Winapi.Windows.HWND,Vcl.Themes.TChildControlInfo>>(" ascii
        $s7 = "ITDictionary<Winapi.Windows.HWND,Vcl.Themes.TSysStyleHook>.TPairEnumerator;" ascii
        $s8 = "\\TEnumerator<System.Generics.Collections.TPair<Winapi.Windows.HWND,Vcl.Themes.TSysStyleHook>>(" ascii
        $s9 = "JTDictionary<Winapi.Windows.HWND,Vcl.Themes.TSysStyleHook>.TValueEnumerator;" ascii
        $s10 = "MTDictionary<Winapi.Windows.HWND,Vcl.Themes.TChildControlInfo>.TPairEnumerator;" ascii
        $s11 = "function ShellExecAsOriginalUser(const Verb, Filename, Params, WorkingDir: String; const ShowCmd: In" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 7511040 and 12 of them
}
