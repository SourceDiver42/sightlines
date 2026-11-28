rule Sightlines_imphash_c93224c6_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-c93224c6"
        date = "2026-11-13"
        campaign = "imphash-c93224c6"
        family = ""
        hash = "0b50fba29577bbdd1894fcc5ae05b70dadaf3276060fde143b4049d83d6add9f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-c93224c6.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "tzlwzzwdsitlh0b19dlg5jmvq5aj6xuee7c44fjuad55xgig5m1g386y11v1x77ueigrfnhjx6dlrjfg97i3q48f0gComponent " ascii
        $s1 = "d exceed limitbaqxjgdlrfsrenzri7mwlm894cws770gi708awqfh14gruc1ttvycx5smjumjvfanzf.gx9096eyy0f3hqt93a" ascii
        $s2 = "6aevb1lbmu4a9ycsasvt4yfv.wlc8z5f17vyzj7tih8rxrafgb8jj98nimmg19mg\\3lz3ueqxy06hi8hdnitcz5vfy8td5x5tmg1" ascii
        $s3 = "parser1v3rgu0eert3gaavrhn6swujj6thcbwfe4qyuyyqj.ax14biuqffyhzj0d1iw0sj7zamtwnhn8ul959m49nij5.ssjhc4f" ascii
        $s4 = "w79z9ghls181xlyq0y4em55l.ynr63vezuxwe1xfbztbdcjeudav816e4xmw04fhie.gjfvb7h36e9h01ahuntdq4ywlycqquqhg" ascii
        $s5 = "ggs5at7jcuv0r4r7fydj5xNext update attempt will madec3ragelay6jw3qqdz53rbifz7lbj64hgi4wv6nl8vuae96jfm" ascii
        $s6 = "yynq9ln6uxi4i9176war4d4zuye1l07q73xw9dt6u5i7qgztc7vwztr8a30labddulcxdx73gjxboverrides endStream opti" ascii
        $s7 = "as1e39x4xzrjgish6yz3mje4function type with name starting with %02X6xiw4adhug89yw801wfd1gf1016ev8s593" ascii
        $s8 = "d1.u5feegnbd41ucmvqwmznfr8qa1t98axwbe65i497x.gswfqslrfcg396sy35c5liy7na6z7tgs0vrizsl1e.nhrc5wmecawcw" ascii
        $s9 = "nl818uu164wmb9l1yitj8mva6vrtuc8tzuqne7j05s1nhigh0j7dbsn56i5wl5u6gv3f478dbefxhw8at33zweq9ahl86gmreagd" ascii
        $s10 = "msq0h0ql3m0hfmhmrbzb8zgl1g9dnjti.irttvexb5vxut9vas5znujsau381vtiyybqjrrqqw.598cmrbfc6tsx4uaz63xsj7zz" ascii
        $s11 = "6ir08run6tczvbvje5.dj41gv4hf4705rqm3v3bineiugeq1yc9a5w84eynd.y1lbv0tds44e1zq6ahjl7q0m4a760ccsw4nwmzz" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1233920 and 12 of them
}
