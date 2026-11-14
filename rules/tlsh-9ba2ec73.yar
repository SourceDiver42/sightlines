rule Sightlines_tlsh_9ba2ec73_wardenstealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-9ba2ec73"
        date = "2026-11-06"
        campaign = "tlsh-9ba2ec73"
        family = "wardenstealer"
        hash = "2dd721f49346d9fe5f42197563815a199f70935cb1d29bb1d9461d96086150f1"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-9ba2ec73.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "42j84q3q0-fqur8a01zf4j7yj0keng2w7pam95ngk8oi5uq-pnku96oh2qyz9fo3va1pdyb8h0cbue07vzrr6-zbwawikwg1bi1h" ascii
        $s1 = "4dvbapeq9qui4u7oj-3m8gicikki4f6pcah57boo339jfmdeyo5m7yz-n6owpezf1qyaj188napne6ku2rzgnz0vuqbz2-8hcw73" ascii
        $s2 = "ipv-mdzwip1n9dcucyho6pkrr7if92u306kb2kivh-8q357rq32a34f57fckveo5g5hvzwfzy95gdga-1j2m0gqum5r80benven0" ascii
        $s3 = "224y6ba393i8wdhd9n1mwh9zeqno-r2v48d4okrpcf5r8q6yy25odba4zzfe71c10v-87pjurcv4g1qp3kndjgmgmv2uhq70gdb9" ascii
        $s4 = "ri5bp37ze3n6jobbg1udm37n-59aa1031yqvae9u0g7y2h5qivo8kyc4rn62pp-mfpnfn4fzh5vgzd6dc30wz3r1j2qnwheu9jfv" ascii
        $s5 = "z8ygjkjue94-5du3ryk6f5dvrz9w5rn7kmg3v7cbh2qh2e64a-q4ey42jh1gbmw6c0jcq9fmyq55p0boocw3iyg-nu88i0r2ywha" ascii
        $s6 = "obncg4b5gd5merj3hn050d4f-27jz3iao7p2ofkri4a63qnpcq4p1mnjvrdviu-o8z3299u7b1h4ugeybz0bk7hp1w87fmrw6ron" ascii
        $s7 = "o-33jdjnh4df55be2gcwki02wzn3b1369c25n8i-yyvgjkp3ib4od2j15aehee4qu0afm1nh496v7-p50hz78nruardoq3og1kyp" ascii
        $s8 = "fd-hqk7oogiyz11rj14u8i2w66pradzmrqai93dv-fmv8gqu54w7byim8wune0o3gi0yfuea45k6m7-qndyr9epn8c0o9o6zh33k" ascii
        $s9 = "01-d8b4dgu71m4bfwbfw3hjp7h9vn96hv7yck5mu-paoynddzhpv1g8j8nf4ih7earin358aojcf70-ejaacwyw9ez025ug1r2q9" ascii
        $s10 = "fk4cf0in2wkn61aoaddgo-9ahibnk6ym4fdhoz4pja3yd3rqcu256j3bh7r-evdgr98nr5qihkokemfiu8pjz98v4guzbygzu-m0" ascii
        $s11 = "0ekpyarvpe843vvdy75-z6dmeohc4r5i926jn0ag4oj0ni8zhh689b8u4-oy19ddo1v9bwa5c0w33e6iciqqzpmm2cbf7z7-bqmy" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1855488 and 12 of them
}
