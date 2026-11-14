rule Sightlines_rich_header_hash_8bf9c76b_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign rich_header_hash-8bf9c76b"
        date = "2026-11-13"
        campaign = "rich_header_hash-8bf9c76b"
        family = ""
        hash = "20cf9d5e6b4626e70d256f8cbc40bbf5f18956055472dace7288d61ad6d21f1a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/rich_header_hash-8bf9c76b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "URL=www.palharesinformatica.com.br" ascii
        $s1 = "Versao.ini34501202044034" ascii
        $s2 = "Name=Palhares Inform" ascii
        $s3 = "d*wc-tu@vwppppppppp" ascii
        $s4 = "Intro=Atualiza" ascii
        $s5 = "AdmVendas.exe" ascii
        $s6 = "DefaultPath=" ascii
        $s7 = "z1[{Dw=X" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 10186784 and 8 of them
}
