rule Sightlines_imphash_da754953_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-da754953"
        date = "2026-11-13"
        campaign = "imphash-da754953"
        family = ""
        hash = "046c62dc9f410e9b542f356b000040ac8a5dfbeb7f27641b4b9844d13460c0b0"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-da754953.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "xcm6jy1k15bbworaq5fbcxm7u3fnzqekonvbiby3ukv0wjuydornaf8p6kmFILTER clause only used figure which flus" ascii
        $s1 = "difkoy8xir6auadz038f1gug6of2v1gvmw18q6cgyb7y3e9xtq621zo35jqjbxfa05kn1tnjmwqptmuxucheck result undefi" ascii
        $s2 = "O2kn71pmvo807gdbxyc63wjgfcdvqem5k8g6xcbu2tct3mot1w63zuia809kzk7erezawot18ikcwdz8e5jgo0nvrfp7qfueyk0n" ascii
        $s3 = " using symbol name associated with network:76faqejtk6ig5g2k2gb1kk3epi6cdtukf535dmqbf9zwk391g2jrezvpu" ascii
        $s4 = "a3e7aygwicizxxfnqp0dutz5edy1pjn6xz6oij8vtw1xyp53be22ug9t1mgxox0static non-static member found multip" ascii
        $s5 = "mnwigckoez7d1x28vtmqn11bjf5wv3zzcktrap23fa9vkjgrf7mzw9t6mm85rgeayenj9zn7jorigin which releases socke" ascii
        $s6 = "icvvorba3kvi82uox5ncurgd7rrfqvw-6mwmpmxpjdokpzi30ro5e766fux9k1b2b5expjy3ny02rkfrk8pojpra-to1z8c20q0t" ascii
        $s7 = "value found wrong typepzceuj9uoaf105tqmr6kdqu0d0doc968zgpr0mgr33eba2zfvutyikdw5k2dw7qm1v9yvkqfwyjtf9" ascii
        $s8 = "selector element type tensorvp1nccqbfktp3ru8mzr0a955g1gq3ji5mb2fk6gax3mogz7xad1opkpodvgmzmdyqe2k8x39" ascii
        $s9 = "k22krbfd18czupn92dk75idb2pfx509y6227pcc-edgidwwfuz5q3a0oqtm617138fd0f0jwocvipoa6meof72vttamr5iq9-uqi" ascii
        $s10 = "jr765286iqiar69t8qcf6gcz1tz7acdpk0prefix with address-of operator cannot have type109cu7k9k0y3vbjap6" ascii
        $s11 = "tu8qw358rzcdy0tukwnd0Precondition failed during resume!2ytugzj0wrm2zjob8p9vyw2n6nww7u8rot0nmvzrapyxb" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1221632 and 12 of them
}
