rule Sightlines_mutex_39df3180_coinminer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign mutex-39df3180"
        date = "2026-11-26"
        campaign = "mutex-39df3180"
        family = "coinminer"
        hash = "23a2f86db2a6456a82db84abc8acd9992708b6c4e424341d462e310dd4b65c33"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/mutex-39df3180.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  font-size:13.5px;line-height:1.55;color:var(--dim);background:#0b0b12}" ascii
        $s1 = "      <activeCodePage xmlns=\"http://schemas.microsoft.com/SMI/2019/WindowsSettings\">UTF-8</activeCod" ascii
        $s2 = ".sub{margin:14px auto 0;max-width:640px;color:var(--dim);font-size:14.5px;line-height:1.65}" ascii
        $s3 = "*NSt6thread11_State_implINS_8_InvokerISt5tupleIJZN2wrL13collect_asyncERKNSt7__cxx1112basic_stringIcS" ascii
        $s4 = ".lock{width:74px;height:74px;margin:0 auto 18px;border-radius:50%;" ascii
        $s5 = "*NSt6thread11_State_implINS_8_InvokerISt5tupleIJZN9wr_injectL5startERKNSt7__cxx1112basic_stringIcSt1" ascii
        $s6 = "@media(max-width:640px){.grid{grid-template-columns:1fr}.top,.body{padding-left:22px;padding-right:2" ascii
        $s7 = "html,body{margin:0;height:100%;background:var(--bg);color:#f2f2f6;" ascii
        $s8 = "  background:linear-gradient(180deg,#12121a,#0b0b11);box-shadow:0 30px 90px rgba(0,0,0,.7);" ascii
        $s9 = ".primary{background:linear-gradient(180deg,#ff3b3b,#b31212);border-color:#ff5757;color:#fff;" ascii
        $s10 = "  const left=Math.max(0,DEADLINE-Math.floor(Date.now()/1000));" ascii
        $s11 = "*NSt6thread11_State_implINS_8_InvokerISt5tupleIJZN8wr_trollL5startERKNSt7__cxx1112basic_stringIcSt11" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 39845888 and 12 of them
}
