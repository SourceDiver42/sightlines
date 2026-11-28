rule Sightlines_tlsh_5934e59a_remcos
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-5934e59a"
        date = "2026-11-25"
        campaign = "tlsh-5934e59a"
        family = "remcos"
        hash = "192d4159f5d72a8cf0c3ceb415f14775c18af1282af084df2472b60032752430"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-5934e59a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "        'uKxdKmkDW7BdGCoxW5ddKCoYdxisC8k2W49GaqNdH0pdGbuSWOhcJc1YWRZcTSkrWRpcImoqWQ45g8kbW67cQCkAvej" ascii
        $s1 = "        'W6evkx3dMSkQgHGDFmo4kuqLWOiBW53dVr/cP8kTsMm9W5ag'," ascii
        $s2 = "dc, _0x19ef77 = new ActiveXObject(_0x19fcc3[_0x2aa533(0x1)]), _0x5b0bfd = _0x19ef77[_0x47669a['MNUCy" ascii
        $s3 = "0x2e2866, _0x4de5bb++ % 0x4) ? _0x39d18e += String['fromCharCode'](0xff & _0x1cfa6e >> (-0x2 * _0x4d" ascii
        $s4 = "iveXObject(_0x19fcc3[_0x47669a[_0x3f247a(0x24, '@mrp')]]);" ascii
        $s5 = "_0x2b5f3f] = _0x2e5a05, _0x2576e5 += String['fromCharCode'](_0x429a03['charCodeAt'](_0x2f5ea3) ^ _0x" ascii
        $s6 = "mE8owWOH+dLlcT8kUW6ZdKmkPnv7dVJ0GW5tcIImmy8o8'," ascii
        $s7 = "27, _0x40b28e = new ActiveXObject(_0x19fcc3[_0x47669a[_0x5f4cbc(0x4b, '!tN[')](_0xe29ea2, 0x0)]);" ascii
        $s8 = "8(0x2)](_0x47669a['rIoFt'](Math[_0x2cff68(0x1e)](), _0x1b17d8[_0x47669a['DpiEh']])));" ascii
        $s9 = "48(0x37, 'kE%4')](_0x36dddc, 0x11)](setTimeout, function () {" ascii
        $s10 = "        return _0xbc7bc[_0x47669a['MNUCy'](_0x396519, 0x1c)](_0x1e0699(0x25, 'Lb@]'), _0x421478, ![]" ascii
        $s11 = "dc, _0x16c48c = _0x36dddc, _0xbc7bc = new ActiveXObject(_0x19fcc3[_0x47669a[_0x1e0699(0x3b, 'i^$0')]" ascii
    condition:
        filesize < 1048576 and 12 of them
}
