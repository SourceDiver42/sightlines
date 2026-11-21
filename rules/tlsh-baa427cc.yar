rule Sightlines_tlsh_baa427cc_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-baa427cc"
        date = "2026-11-15"
        campaign = "tlsh-baa427cc"
        family = ""
        hash = "1a0d66061b1a2b5ad8bf396a4ac38254eba2a711b4b0d3bdc11acde14cc969ff"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-baa427cc.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = " deflate 1.3.2 Copyright 1995-2026 Jean-loup Gailly and Mark Adler " ascii
        $s1 = "JFIF extension marker: JPEG-compressed thumbnail image, length %u" ascii
        $s2 = "Start Of Frame 0x%02x: width=%u, height=%u, components=%d" ascii
        $s3 = " inflate 1.3.2 Copyright 1995-2026 Mark Adler " ascii
        $s4 = "Invalid JPEG file structure: two SOF markers" ascii
        $s5 = "Corrupt JPEG data: found marker 0x%02x instead of RST%d" ascii
        $s6 = "Invalid JPEG file structure: two SOI markers" ascii
        $s7 = "Adobe APP14 marker: version %d, flags 0x%04x 0x%04x, transform %d" ascii
        $s8 = "tRNS chunk has out-of-range samples for bit_depth" ascii
        $s9 = "Unsupported JPEG process: SOF type 0x%02x" ascii
        $s10 = "JFIF extension marker: RGB thumbnail image, length %u" ascii
        $s11 = "JFIF extension marker: type 0x%02x, length %u" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 10 of them
}
