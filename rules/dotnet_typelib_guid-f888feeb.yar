rule Sightlines_dotnet_typelib_guid_f888feeb_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-f888feeb"
        date = "2026-10-15"
        campaign = "dotnet_typelib_guid-f888feeb"
        family = ""
        hash = "0fdf8b638918ac7a04c36e6ea150548dcd245caa8674601c8a9d5905e77f9bc3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-f888feeb.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "\"!)(*(+(,(.-/-0-21314151617198;:<:NMOMPMQMRMSMWVXVYVZV[V^]gfml{z}|" wide
        $s1 = "Are you mixing protobuf-net and protobuf-csharp-port? See https://stackoverflow.com/q/11564914/23354" wide
        $s2 = "      <dpiAwareness xmlns=\"http://schemas.microsoft.com/SMI/2016/WindowsSettings\">PerMonitorV2, PerM" ascii
        $s3 = "Org.BouncyCastle.X509.Allow_Non-DER_TBSCert" wide
        $s4 = "SELECT * FROM Win32_OperatingSystem WHERE Primary='true'" wide
        $s5 = "5ProtoBuf.Meta.MetaType+<GetAllGenericArguments>d__104" ascii
        $s6 = " length; see https://stackoverflow.com/q/2152978/23354" wide
        $s7 = "'signatureAndHashAlgorithm' cannot be null for (D)TLS 1.2+" wide
        $s8 = "invalid length for GOST3410_2012 public key" wide
        $s9 = "invalid length for GOST3410_2001 public key" wide
        $s10 = "SELECT * FROM Win32_DisplayConfiguration" wide
        $s11 = "<149ef234-534f-4248-9e1b-6af875c1ef7c><PrivateImplementationDetails>" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 6660096 and 10 of them
}
