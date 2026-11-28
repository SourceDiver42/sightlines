rule Sightlines_tlsh_e81c7a2c_darktortilla
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-e81c7a2c"
        date = "2026-11-10"
        campaign = "tlsh-e81c7a2c"
        family = "darktortilla"
        hash = "349e7b95bfbfb4cc47d217ad7ad258e0419e588cd47b84fb3dcee2e4dbcee405"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-e81c7a2c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" ascii
        $s1 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator" ascii
        $s2 = "Property can only be set to Nothing" wide
        $s3 = ".NETFramework,Version=v4.6" ascii
        $s4 = "m_ThreadStaticValue" ascii
        $s5 = ".NET Framework 4.6" ascii
        $s6 = "My.MyProject.Forms" ascii
        $s7 = "Dispose__Instance__" ascii
        $s8 = "Create__Instance__" ascii
        $s9 = "My.Application" ascii
        $s10 = "My.WebServices" ascii
        $s11 = "yyyyMMdd-HHmmss" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 3373056 and 12 of them
}
