rule Sightlines_tlsh_08d2df2c_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-08d2df2c"
        date = "2026-11-24"
        campaign = "tlsh-08d2df2c"
        family = ""
        hash = "025465772e29db68cf34a2830ba71b67139575d578fcba7ae48686d47ed26cad"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-08d2df2c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "org/bouncycastle/asn1/x509/PK" ascii
        $s1 = "org/bouncycastle/crypto/tls/PK" ascii
        $s2 = "org/bouncycastle/crypto/PK" ascii
        $s3 = "com/jagex/oldscape/pub/PK" ascii
        $s4 = "org/bouncycastle/asn1/PK" ascii
        $s5 = "compilercontrol.jsonPK" ascii
        $s6 = "com/jagex/oldscape/PK" ascii
        $s7 = "org/bouncycastle/PK" ascii
        $s8 = "jUy]9ipRUU5e&JITs$" ascii
        $s9 = "client.serialPK" ascii
        $s10 = "8~-VD<ovRp2yW" ascii
        $s11 = "p]$5C&?VsGLN7" ascii
    condition:
        filesize < 8683010 and 12 of them
}
