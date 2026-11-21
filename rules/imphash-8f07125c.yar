rule Sightlines_imphash_8f07125c_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-8f07125c"
        date = "2026-11-18"
        campaign = "imphash-8f07125c"
        family = ""
        hash = "18051c0f913686cafb8984889e1876b657b87cc12c993e3c54545ce7b11c21cd"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-8f07125c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ObjMakeUpvar called with null effect targetacwt1qqo60j3d951b67z21165yw7v2doqxbq7ipw0niqi614cawnfdfc2" ascii
        $s1 = "3f4t0fafpxC:\\ProgramData\\hasp\\aownoteord.inf5c0470u9kpvok524ex7uwptxze1ti40b20025i3hzob5dnk4o5qaatsj" ascii
        $s2 = "3fhx94eqse0e6ncje0b7ph2u6ft1av5s39xuh16v07i7vqgio7nsdqzubdeobfEditContext only associated with Docum" ascii
        $s3 = "xzd0w92w1uj4bjuia5t0112xx9yudz32fixppxvge2ajztby6p0yp0a9ktou9wqd51v16b4t04jnagixChild process could " ascii
        $s4 = "find library:k25abdc0znyb2e54cw2vb32a6fw2v11tfzjji94qcoeu7ppq53p2Initializing from global requires c" ascii
        $s5 = "wvf22i041e1w0zkj0dny3pacaffgq1i0ux5eoc6nok6sioc0tghz1b2di07zubqgkvxnuxa69eq99cwg1this other right so" ascii
        $s6 = "soknt3uxw7yqi2xxpqsa09yeg3k0ygikid9y5bz3ja0k26kf203x1b1nh1hdo422ep9feo1same too place what are would" ascii
        $s7 = "n3qp3b9z3511kyivc3qosvup2aoya3gkfb3zn6g4i72p222t1kn4anx7vjh6i96ypz7xpyq6o9dj4o1Renewing based time s" ascii
        $s8 = "do6ho0qzge4dhxcankgxit1vwnie7dub0tva0jq22sqbsacp1yp3pijinjtcn16ocbo921caysfgi62fzu4tpkuds5hv5xg4dwkh" ascii
        $s9 = "vci0hy9uqyoi3ct6731iyhepqg0f2gdo15cab0fewp4k6ijkqj2e1qgag9pb3kn52kjcwstelteodsobsy07nnfzof3hqajaa25x" ascii
        $s10 = "4fndx6wsqu5uuovyk1aixexplicit data sharing attributesjb4nxk54ki7ootv1h6np9i264y70253g3dekdbj5i797gk7" ascii
        $s11 = "eq5sht4h9n43ibfne5kdijvjz34ofh67ba1pznbye39vwibv29ab0u2vfe1zSetLocalDescription failed because that " ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1215488 and 12 of them
}
