rule Sightlines_tlsh_71f1b57d_purerat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-71f1b57d"
        date = "2026-11-09"
        campaign = "tlsh-71f1b57d"
        family = "purerat"
        hash = "258022c9ee70b92625662def214028b4d2a99edab59a9a1e702cd777dbfdb462"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-71f1b57d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = ",\".,/-05196<8=:>;C<F=I>L?M@PASBVCYD\\E_FbGeHfIiJlKoMrNsO}P" wide
        $s1 = "Are you mixing protobuf-net and protobuf-csharp-port? See https://stackoverflow.com/q/11564914/23354" wide
        $s2 = " length; see https://stackoverflow.com/q/2152978/23354" wide
        $s3 = "TimeSpan was unexpectedly too big for DiscriminatedUnion128Object" wide
        $s4 = "; please see https://stackoverflow.com/q/14436606/23354" wide
        $s5 = "Guid was unexpectedly too big for DiscriminatedUnion128Object" wide
        $s6 = "TimeSpan was unexpectedly too big for DiscriminatedUnion64Object" wide
        $s7 = "]Please use RuntimeTypeModel.Default.InferTagFromNameDefault instead (or on a per-model basis)" ascii
        $s8 = "DateTime was unexpectedly too big for DiscriminatedUnion128Object" wide
        $s9 = "import \"protobuf-net/bcl.proto\"; // schema for protobuf-net's handling of core .NET types" wide
        $s10 = "DateTime was unexpectedly too big for DiscriminatedUnion64Object" wide
        $s11 = ",See https://github.com/mgravell/protobuf-net" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
