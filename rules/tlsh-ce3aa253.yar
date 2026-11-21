rule Sightlines_tlsh_ce3aa253_wardenstealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-ce3aa253"
        date = "2026-11-06"
        campaign = "tlsh-ce3aa253"
        family = "wardenstealer"
        hash = "321e363c47fee93a966b1ee68b495b6de60ad2da77105edc6ca39e9c071c0bf0"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-ce3aa253.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "oemgp36fpalsl-3c9tpmgu7ej9vbficrbvpgwsebf5avh9h28zfj960t7k8l-b64rm7vnw7lnh6cok004rtwl8sjngu9xoz42w5u" ascii
        $s1 = "lh9jgx83kbntxrwxko7ov5wz9czr-vu4op3gnlw2ep9fuaa7cmuw2cte4uioga68g4nrpw6xcjp-kcleh5m3ts048uf3b5zisea6" ascii
        $s2 = "uuw-jgztx3pfmue5liaka46krtvk9joeanskjl7az6vbic0h6f-wv2ctnovicrwbslw8ixzjf5e8zp098p5e6h2huw7pmg83c-wh" ascii
        $s3 = "3a7w0si3v-llbcz432akm220r4xh5rvjmxcgo9jleuxe4j7mnxukbzbn-cut9pk6hapuekf5o0o4xt2wn8ftjx9p6ugi89cruom5" ascii
        $s4 = "ljncreotnuz7cv095nv93w9neb4k-tcas965hs5x90b809j2xaupofl5ki77h3ejs624mlbun6g-73fjppg88bzwmh8guifmmpmg" ascii
        $s5 = "t2562c83bjiba-88m4nmr8cj7wtp7icl9guzlfw5njk9mujrwi97gsglblhg-e3fgokzmz7nx3jrxh4pozvknr8aeo0t6rfscv76" ascii
        $s6 = "hz098uz9xjfosnnag278bcrpk3m5zk-uljgow0s6tlm45e3fm6v4na7b9hwspez0ek32vmrk4hubz-as38gzibo52lv5j488rc7e" ascii
        $s7 = "2twsa66fc798kkc0lnttrg8eu7crv-xbxaju20r53kmcxoes5rm9245osimnl2m8heza40b3ow57-jgfxuppbpzlvzx4ze7mbf55" ascii
        $s8 = "6jos3mklhbecjs-p383nrn0mei0klpve5ephx3voomc2v40tuturul02cf8a4-gsmza2fn8a97c4k9bb9kklb96ghw3zxr4kio5h" ascii
        $s9 = "b5m2wzf46ibfppaiss76itl9cl6uzxtgcs-5n3cuxjnm80bf28gfelje9r79rvkfibg8wl3zhesjgwn0f-h97mhkbmp0o5kt4h4s" ascii
        $s10 = "mb6jk-ipu7he5ppsmfej0fpz5abnnolmk6cgfi30pjbaz8ltn2fe-jbr44hxe8owvlvrisxb590o92336u9nmtf4jjgwra5ahwz-" ascii
        $s11 = "0uubahkfwg-gg84ote0flu3jcx8an4ico9zpjm0e6uep6bh95tl5l9r62-93sp88ccm2owz6a6z7rjtekhrtan6fv4wans0vujg7" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1777664 and 12 of them
}
