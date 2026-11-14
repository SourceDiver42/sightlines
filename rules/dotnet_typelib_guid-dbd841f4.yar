rule Sightlines_dotnet_typelib_guid_dbd841f4_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-dbd841f4"
        date = "2026-11-11"
        campaign = "dotnet_typelib_guid-dbd841f4"
        family = ""
        hash = "7f912b28a07c226e0be3acfb2f57f050538aba0100fa1f0bf2c39f1a1f1da814"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-dbd841f4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Microsoft.CSharp.RuntimeBinder.CSharpArgumentInfoFlags, Microsoft.CSharp, Version=4.0.0.0, Culture=n" wide
        $s1 = "Microsoft.CSharp.RuntimeBinder.CSharpArgumentInfo, Microsoft.CSharp, Version=4.0.0.0, Culture=neutra" wide
        $s2 = "Cannot deserialize the current JSON object (e.g. {{\"name\":\"value\"}}) into type '{0}' because the typ" wide
        $s3 = "Cannot deserialize the current JSON array (e.g. [1,2,3]) into type '{0}' because the type requires a" wide
        $s4 = "Invalid extension data attribute on '{0}'. Member '{1}' type must implement IDictionary<string, JTok" wide
        $s5 = "Unexpected JSON token when reading DataTable. Expected StartArray, got {0}." wide
        $s6 = "System.Collections.Generic.IDictionary<System.String,Newtonsoft.Json.Linq.JToken>.get_Values" ascii
        $s7 = "Unexpected initial token '{0}' when populating object. Expected JSON object or array." wide
        $s8 = "Serialization Error Callback '{1}' in type '{0}' must have two parameters of type '{2}' and '{3}'." wide
        $s9 = "Expected Array token while parsing enum values, got {0}." wide
        $s10 = "<TryBuildImmutableForDictionaryContract>b__25_1" ascii
        $s11 = "System.Collections.Generic.IDictionary<System.String,Newtonsoft.Json.Linq.JToken>.Values" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1400672 and 12 of them
}
