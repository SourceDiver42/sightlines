rule Sightlines_dotnet_typelib_guid_f888feeb_quasarrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-f888feeb"
        date = "2026-10-22"
        campaign = "dotnet_typelib_guid-f888feeb"
        family = "quasarrat"
        hash = "0fdf8b638918ac7a04c36e6ea150548dcd245caa8674601c8a9d5905e77f9bc3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-f888feeb.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Are you mixing protobuf-net and protobuf-csharp-port? See https://stackoverflow.com/q/11564914/23354" wide
        $s1 = "      <dpiAwareness xmlns=\"http://schemas.microsoft.com/SMI/2016/WindowsSettings\">PerMonitorV2, PerM" ascii
        $s2 = "Org.BouncyCastle.X509.Allow_Non-DER_TBSCert" wide
        $s3 = "SELECT * FROM Win32_OperatingSystem WHERE Primary='true'" wide
        $s4 = "5ProtoBuf.Meta.MetaType+<GetAllGenericArguments>d__104" ascii
        $s5 = " length; see https://stackoverflow.com/q/2152978/23354" wide
        $s6 = "'signatureAndHashAlgorithm' cannot be null for (D)TLS 1.2+" wide
        $s7 = "invalid length for GOST3410_2012 public key" wide
        $s8 = "invalid length for GOST3410_2001 public key" wide
        $s9 = "SELECT * FROM Win32_DisplayConfiguration" wide
        $s10 = "<149ef234-534f-4248-9e1b-6af875c1ef7c><PrivateImplementationDetails>" ascii
        $s11 = "Unrecognized curve OID for GostR3410x2001 private key" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 10258432 and 3 of them
}
