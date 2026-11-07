rule Sightlines_tlsh_b65db6c7_redlinestealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-b65db6c7"
        date = "2026-10-20"
        campaign = "tlsh-b65db6c7"
        family = "redlinestealer"
        hash = "4f1271f35cb5bfdb456481302e219e5b8e7341bf1e871bd5f4cdc6636da18929"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-b65db6c7.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "oBIbhKdNyoXfV6gkfTPkFMkt5Ppq4mce6/F8DX/bZ7PjnCIAZ6hWLps3PUaGlNxU2a9Tvg1UehNiB+wE/c1YSwLx/xm6dAJYQn0B" ascii
        $s1 = "9KGpatiI0Jel7lF4b8eSmA3v7Vk6k+HdjyV2Lrz7sxSDUFoCWLJV8N6BpX0kvAcyAQyC9yAmhZ7w3pGJQgHvCiqPRm/F3EPrnYr1" ascii
        $s2 = "T6MKMsdeznLFwv9qO1mO0a6sS+rIrhHZunh+4/nmA3soj50AZbFWDRUri1T2I/8jgSv4NcBaDChukCtA4TfEXZXGtSZXpXltJuB5" ascii
        $s3 = "20wTevRxSrOLtL+ItN/MxjQLpkVGP4cPqXaD7DTmNZJcR74KC/yuK1H3wX54MUt3znmYzzLPOg8TGiRHJlVihbAix0zsfatY979K" ascii
        $s4 = "H7YXgSo3naVob59LgmrsRMa69cuH2d/81GUVzWVC4sIftO07B21k6vf0nQx9g4qaYYgKh43BclzvWBmeC7X/H+7zpNEwTx35PewP" ascii
        $s5 = "G2IOolg/jx3zAGnES7HxtOCFd5ZD165cDlO++Xdy2N74n8hBUVRMizrKYrjis3baooNeqUWOAEtQ0WQ/r9Qa7yAYv3ql0lV9L5CK" ascii
        $s6 = "Gm5yMIAKe3hhFB2RzYb3orxQH8tUapqnVPo+dQ/syaegL4AgBP0IsITZP9TCcJP4UqpVMk/n+dlf1NJxXLg9O59EryZeCYIR45Uw" ascii
        $s7 = "igW+KGVEuSdFE/blKdyj3oFkfsTYV7/wRiaLJBHwQ2YQzOzakFxcF3U96NpnyclZOekhZXBkIMWfbE4yKKT86TqiezE6j51LyC0f" ascii
        $s8 = "a50tmyXNUcnahqcFLDrnVJwiT3qIoeD6uARb9vIXC8C+6dSOZUATn95lBlq+fMujlBpGFQJN8HuhGKjtkdaN1P+yhSLQpqWfP0bt" ascii
        $s9 = "j+uTzmraIN2OU55zEK0AT9SXRQkgutH8acPJpVPCtjThdKsU7BSm2vKinl2Lc/a20KWbmS4ClGpJoAsNlCOb6ZNy6EDzPKKfvF18" ascii
        $s10 = "dSG7zFr4l4RmqDDAmogQ+NlumRkCLH8hAPOoe1XTVY/pxfgmM3Bq3GIvkVnIDqO/2i5DX9g8Cxs3ZxH+8LsBRoT65UbojBJ3fTcz" ascii
        $s11 = "3EXPXJi/0TrPYilBPZbRehywv1yYR8+bY4Fra/KLlpikRsJAF7HQlH+96Sfp5wpzTUUm608OPDCgdKcdm1VsXGIuLJZqk3wRlVu0" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
