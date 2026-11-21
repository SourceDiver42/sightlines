rule Sightlines_tlsh_eebf4b75_gcleaner
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-eebf4b75"
        date = "2026-11-11"
        campaign = "tlsh-eebf4b75"
        family = "gcleaner"
        hash = "17033faffac3c967a6bd8ef494191a293a3782dbf730a040c4da52f66825d2b0"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-eebf4b75.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ID-Attribut ist weder als #IMPLIED noch als #REQUIRED deklariert" ascii
        $s1 = "Atrybut ID nie jest zadeklarowany ani jako #IMPLIED ani #REQUIRED" ascii
        $s2 = "http://www.w3.org/2001/XMLSchema-instance" ascii
        $s3 = "Ein IDREF- bzw. IDREFS-Attribute verweist auf ein nicht vorhandenes Ziel" ascii
        $s4 = "Als \"#REQUIRED\" deklariertes Attribut nicht gefunden" ascii
        $s5 = "Error creating file \"%s\"5Unhandled Xerces DOM error (no message available): %d" wide
        $s6 = "Alt+ Clipboard does not support Icons/Menu '%s' is already being used by another form" wide
        $s7 = "Atributo ID no ha sido declarado como #IMPLIED ni como #REQUIRED" ascii
        $s8 = "ID attribuut is niet gedefinieerd als #IMPLIED of #REQUIRED" ascii
        $s9 = "Bits index out of range*Can't write to a read-only resource streamECheckSynchronize called from thre" wide
        $s10 = "List index out of bounds (%d)+Out of memory while expanding memory stream" wide
        $s11 = "Ein ENTITY- bzw. ENTITIES-Attribute verweist auf eine nicht analysierte Entit" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2525728 and 12 of them
}
