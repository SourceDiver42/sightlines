rule Sightlines_tlsh_61de42a4_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-61de42a4"
        date = "2026-11-17"
        campaign = "tlsh-61de42a4"
        family = ""
        hash = "063e22c1be0daef294d279d7fda829c1f4cc722a8519665f1bde9b5954036096"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-61de42a4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "    const _useRcExpand = _rcSkin && !!document.getElementById('cf-expand');" ascii
        $s1 = "or.platform || '')) && !/iPhone|iPad|iPod|Windows/i.test(navigator.userAgent));" ascii
        $s2 = "            const _0xwasm = 'AGFzbQEAAAABpYCAgAABYAF/AX8Bf2GAgIAAAQMBAQAHA6KAgIAAA2V4cAEGZ2V0X3N0YXR" ascii
        $s3 = "        window.parent.postMessage({ captcha_verified: true }, _vault.t || '*');" ascii
        $s4 = "    const _isWin = true || /Windows|WinNT|WOW64|Win32|Win64/i.test(navigator.userAgent);" ascii
        $s5 = "        const elapsed = Math.max(0, Math.round((Date.now() - _visitStarted) / 1000));" ascii
        $s6 = "        challengeEl.addEventListener(_0x4b3c(25), (e) => {" ascii
        $s7 = "    const _rcSkin = document.documentElement.getAttribute('data-rc-skin') === '1';" ascii
        $s8 = "            loader.innerHTML = '<svg class=\"rc-arc-svg\" viewBox=\"0 0 56 56\" aria-hidden=\"true\"><circ" ascii
        $s9 = "        const wrap = document.getElementById('cf-challenge-wrap');" ascii
        $s10 = "        if (/Win/i.test(plat) || /Windows|WinNT|WOW64|Win32|Win64/i.test(ua)) return 'Windows';" ascii
        $s11 = "le class=\"rc-arc-path\" cx=\"28\" cy=\"28\" r=\"22\" fill=\"none\" stroke-width=\"9\" stroke-linecap=\"square\"/>" ascii
    condition:
        filesize < 1048576 and 12 of them
}
