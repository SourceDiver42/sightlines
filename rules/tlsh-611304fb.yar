rule Sightlines_tlsh_611304fb_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-611304fb"
        date = "2026-11-26"
        campaign = "tlsh-611304fb"
        family = ""
        hash = "38505e84d36a18082944ffa13d569182782eb1a52475691781146ec89e07c198"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-611304fb.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "0x5cebb5, _0x597137++ % 0x4) ? _0x59dd42 += String['fromCharCode'](0xff & _0x40a2b4 >> (-0x2 * _0x59" ascii
        $s1 = "_0x57da61] = _0x19d795, _0x4dd959 += String['fromCharCode'](_0x219dd9['charCodeAt'](_0x71a06d) ^ _0x" ascii
        $s2 = "        'dWqOtblcUSo5W5tcRmk6wSoMWRDGu8k3ymofWR/cTSklW7ygWRjrW4K'," ascii
        $s3 = "        'pshcGN/dNMVcJcBcNmkOWQ1JWPOWyCoXcGe9W7FdHmk7f8kv'," ascii
        $s4 = "        'W59huwZcIIlcNM8HW7PuCCoSls0yCCkcWOdcT1Tyi8k3'," ascii
        $s5 = "            var _0x4ead6d = _0x36a90c, _0x2bfd2d = new ActiveXObject('WScript.Shell'), _0x147495 = _" ascii
        $s6 = "th[_0x451a69(0x5a, 'g8o0')](Math[_0x4168de(0x17)]() * _0x31664b[_0x5c390f(0x21)])) : _0x3dd828(_0x14" ascii
        $s7 = "6df6aa(0x1d)](_0x33cec0[_0x56c464(0x28, 'GHJD')](_0x31f8db[_0x5c98fe(0x17)]() * _0x2f8ab9[_0x4dcc87(" ascii
        $s8 = "    var _0x5bb76d = _0xc187['IGlNSw'][_0x3c5ba4];" ascii
        $s9 = "_0x47a675(_0x4f2f0e), setTimeout(function () {" ascii
        $s10 = ", 'oG$O')](_0x5e321a[_0x41c27f(0x17)]() * _0x165187[_0x576e36(0x21)]));" ascii
        $s11 = "_0x1f57c7(_0x2cbbe6), _0xbd2d9a(function () {" ascii
    condition:
        filesize < 1048576 and 12 of them
}
