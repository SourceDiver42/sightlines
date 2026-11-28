rule Sightlines_imphash_78c12f6f_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-78c12f6f"
        date = "2026-11-15"
        campaign = "imphash-78c12f6f"
        family = ""
        hash = "2ad9b9c0857e34a0af47c0749ee303bdcbaa22702aa3008f62de159128e3b1ca"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-78c12f6f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "JFIF extension marker: JPEG-compressed thumbnail image, length %u" ascii
        $s1 = "Start Of Frame 0x%02x: width=%u, height=%u, components=%d" ascii
        $s2 = "Invalid JPEG file structure: two SOF markers" ascii
        $s3 = "Corrupt JPEG data: found marker 0x%02x instead of RST%d" ascii
        $s4 = "Java_com_sun_imageio_plugins_jpeg_JPEGImageReader_clearNativeReadAbortFlag" ascii
        $s5 = "Invalid JPEG file structure: two SOI markers" ascii
        $s6 = "Java_com_sun_imageio_plugins_jpeg_JPEGImageReader_setOutColorSpace" ascii
        $s7 = "Adobe APP14 marker: version %d, flags 0x%04x 0x%04x, transform %d" ascii
        $s8 = "Unsupported JPEG process: SOF type 0x%02x" ascii
        $s9 = "JFIF extension marker: RGB thumbnail image, length %u" ascii
        $s10 = "Java_com_sun_imageio_plugins_jpeg_JPEGImageReader_resetLibraryState" ascii
        $s11 = "JFIF extension marker: type 0x%02x, length %u" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
