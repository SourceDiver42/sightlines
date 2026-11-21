rule Sightlines_tlsh_6aa3eeb9_wardenstealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-6aa3eeb9"
        date = "2026-11-19"
        campaign = "tlsh-6aa3eeb9"
        family = "wardenstealer"
        hash = "c5e8906d63b53ecc858c42c32b861c3870698f0ab14c735dd8d4d4bfe4bffe69"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-6aa3eeb9.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "8bjyast4wju9uuyq61klto5aq4zrw6-fi4nrn0d9s4l7zdjv1vsa10gmfa8v6y2bbp7op7jj8lrki-9ukhvv78g5inpwzghorpsd" ascii
        $s1 = "5vruh-ny2tfs0s502wpakj4qwqpmsiyjp1uw6bwm6ubdgmh7tlzt-rkdo10171szb7a5jl828s9vgati0fzi6k96s5o9mlzjgm4-" ascii
        $s2 = "5y88mg6g7dbks0oarjqkg02rs6bfq-z582vo6wov0ujdhzjtknphtzt0i9pdpaf7g44a4vz4qmai-vnlulg9f8ony1dyu5woovz7" ascii
        $s3 = "zz-ob1fvpo740gvs088nolyit4hh49q2tu1r2j1gpkdmylus1-hidlzv2iz0rk61p05ivnwq9j5b7wfryilau8mkyk9a79rf-701" ascii
        $s4 = "agyau7oos9p22droybqzhyd6lm1-db7vigourj0k5zizpn9jlfvqn2zu8p68vghbwmd0qh640v-t1dnm74ks5pfqwahad05ukdn2" ascii
        $s5 = "1fmzpnvutsdzdluaub5u6ikos4jyf-pq1mk7vs985ud1j74nry1prl4tw27jgmnlvsho2hzl67a8-f0ihm7wd94qga8k9d2izagd" ascii
        $s6 = "0wg40n-ymltbn1951k6g1jkls7paz1a4rqh0zj2ums74t2yf50uig-g8q9i8bol48baivr5mooz5vv0ku6jhw1btqo91dfo0dso2" ascii
        $s7 = "qvrvy4ftiwgy9b5h06f050fj6b6uym8v-6uzukoyan12k2z7j0os1rt9u78ph1hrn8wgwgdvls9n42i-dfy1fp2rbsgqz6p54ikw" ascii
        $s8 = "uslaupvb2j8j0zonpy09t5wdoa9818gt6-iyo80269vg10hontlf4my470drwk2s2zrpif8bj41frqi7-bmlzn6t6g8qfpfb2dah" ascii
        $s9 = "u4dbit0noi1ya07ydltygd4hbvzlf0ghu2ajwup-fubdmt8q59pvn9jay4ri79ws6rns1r8h2rpgoujkvp2au2-1z578i41q64r7" ascii
        $s10 = "low8fohkrn-r2bihj8d1tjbv5narytgarlsz9fspd0snwq4y7h6qogm2d-uoyqlbsipwl7ukp2zqb6z4t8y7lb6yf0ts7mh52duv" ascii
        $s11 = "4molv95s1bwn7nab1spr89-64nad842vwfljaykvrf7ptsoq7hagt7ybdqa45z4ophbpq-kfd5izu69v0hig2h2sk0u7trh6z8av" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1517568 and 12 of them
}
