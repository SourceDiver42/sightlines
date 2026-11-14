rule Sightlines_tlsh_890f7e0a_gcleaner
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-890f7e0a"
        date = "2026-11-07"
        campaign = "tlsh-890f7e0a"
        family = "gcleaner"
        hash = "1a0ea15923467dd4ea00efcaddc815ab14a0bcd9433f676dbbd413e3e8f89240"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-890f7e0a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "drive.usercontent.google.com/download?id=1YBVIDkZgygNfUU2rbJXXCYdrzay5rMdY&export=download&authuser=" ascii
        $s1 = "0J7EFGABCeuvdDK489SEV56ewf332Nd123sfeW4werf5FDGwYZRtwz" ascii
        $s2 = "aAbBcCdDeFgGhHIjmMnprRStTuUVwWxXyYzZM" ascii
        $s3 = "Accept-Charset: iso-8859-1, utf-8, utf-16, *;q=0.1" ascii
        $s4 = "The program can't start because MSVCP140.dll is missing from your computer. Try reinstalling the pro" ascii
        $s5 = "Accept-Language: ru-RU,ru;q=0.9,en;q=0.8" ascii
        $s6 = "Accept-Encoding: deflate, gzip, x-gzip, identity, *;q=0" ascii
        $s7 = "Accept: text/html, application/xml;q=0.9, application/xhtml+xml, image/png, image/jpeg, image/gif, i" ascii
        $s8 = "FileHeader.Machine != HOST_MACHINE!" ascii
        $s9 = "Signature != IMAGE_NT_SIGNATURE!" ascii
        $s10 = "alignedImageSize != AlignValueUp!" ascii
        $s11 = "DOS header size is not valid!" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
