rule Sightlines_dotnet_typelib_guid_dbd841f4_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-dbd841f4"
        date = "2026-10-17"
        campaign = "dotnet_typelib_guid-dbd841f4"
        family = ""
        hash = "500eb5560aae4d3a4d7dc4c61a880906ed0231f1a636113f74778b86eaf979b1"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-dbd841f4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Cannot deserialize the current JSON object (e.g. {{\"name\":\"value\"}}) into type '{0}' because the typ" wide
        $s1 = "Cannot deserialize the current JSON array (e.g. [1,2,3]) into type '{0}' because the type requires a" wide
        $s2 = "Invalid extension data attribute on '{0}'. Member '{1}' type must implement IDictionary<string, JTok" wide
        $s3 = "Unexpected JSON token when reading DataTable. Expected StartArray, got {0}." wide
        $s4 = "System.Collections.Generic.IDictionary<System.String,Newtonsoft.Json.Linq.JToken>.get_Values" ascii
        $s5 = "Unexpected initial token '{0}' when populating object. Expected JSON object or array." wide
        $s6 = "Serialization Error Callback '{1}' in type '{0}' must have two parameters of type '{2}' and '{3}'." wide
        $s7 = "Expected Array token while parsing enum values, got {0}." wide
        $s8 = "<TryBuildImmutableForDictionaryContract>b__25_1" ascii
        $s9 = "System.Collections.Generic.IDictionary<System.String,Newtonsoft.Json.Linq.JToken>.Values" ascii
        $s10 = "MJsonNet35BinaryCompatibility will be removed in a future version of Json.NET." ascii
        $s11 = "Set JConstructor values with invalid key value: {0}. Argument position index expected." wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1400672 and 12 of them
}
