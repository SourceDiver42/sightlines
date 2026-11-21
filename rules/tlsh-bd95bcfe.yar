rule Sightlines_tlsh_bd95bcfe_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-bd95bcfe"
        date = "2026-11-15"
        campaign = "tlsh-bd95bcfe"
        family = ""
        hash = "02735b9b7d80d371b9ad3cd560a72ef6f161a2c503cb64dadb9886d8df645f24"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-bd95bcfe.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "INFLATER_inflateFully: Compressed data corrupted" ascii
        $s1 = " deflate 1.3.2 Copyright 1995-2026 Jean-loup Gailly and Mark Adler " ascii
        $s2 = "INFLATER_inflateFully: Unexpected end of stream" ascii
        $s3 = " inflate 1.3.2 Copyright 1995-2026 Mark Adler " ascii
        $s4 = "zlib returned Z_VERSION_ERROR: compile time and runtime zlib implementations differ" ascii
        $s5 = "ZIP_Read: corrupt zip file: invalid entry size" ascii
        $s6 = "invalid CEN header (bad compression method)" ascii
        $s7 = "Java_java_util_zip_CRC32_updateByteBuffer0" ascii
        $s8 = "invalid END header (bad central directory offset)" ascii
        $s9 = "Java_java_util_zip_Inflater_setDictionaryBuffer" ascii
        $s10 = "invalid END header (bad central directory size)" ascii
        $s11 = "Java_java_util_zip_Adler32_updateByteBuffer" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 10 of them
}
