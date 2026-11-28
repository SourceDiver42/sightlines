rule Sightlines_imphash_b214d791_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-b214d791"
        date = "2026-11-15"
        campaign = "imphash-b214d791"
        family = ""
        hash = "8c0a00c930c0ee4a40fc2832c43b16a8008be0d915624ac744300b9fe2663c8b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-b214d791.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Java_sun_security_smartcardio_PCSC_SCardEstablishContext" ascii
        $s1 = "Java_sun_security_smartcardio_PCSC_SCardBeginTransaction" ascii
        $s2 = "Java_sun_security_smartcardio_PCSC_SCardGetStatusChange" ascii
        $s3 = "Java_sun_security_smartcardio_PCSC_SCardDisconnect" ascii
        $s4 = "Java_sun_security_smartcardio_PCSC_SCardEndTransaction" ascii
        $s5 = "Java_sun_security_smartcardio_PCSC_SCardListReaders" ascii
        $s6 = "Java_sun_security_smartcardio_PCSC_SCardControl" ascii
        $s7 = "Java_sun_security_smartcardio_PCSC_SCardTransmit" ascii
        $s8 = "Java_sun_security_smartcardio_PCSC_SCardConnect" ascii
        $s9 = "sun/security/smartcardio/PCSCException" ascii
        $s10 = "Java_sun_security_smartcardio_PCSC_SCardStatus" ascii
        $s11 = "java/lang/OutOfMemoryError" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
