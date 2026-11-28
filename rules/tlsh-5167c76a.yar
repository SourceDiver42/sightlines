rule Sightlines_tlsh_5167c76a_agenttesla
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-5167c76a"
        date = "2026-11-26"
        campaign = "tlsh-5167c76a"
        family = "agenttesla"
        hash = "05e7a8c51151c0207ae5b08e65bd53571cadfa3397d0c7f161fa03b5cdc2f44c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-5167c76a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "1weQ4NaWA0NWoUBlB0JxUYFD4MVjcwPh1zVQkFJi8ADjYNOTMETXAFBjU9NB8ROGgMLnB8EiwHahNsBykIKicLDScSCWw3ODNUNh" ascii
        $s1 = "oiPWoOcEACBQQOAykGDA89HApzdSMWCy8DVysyOQJRSRk5HDIAATYJEx0LT1suEjY4DmwIAjQXC3pQEiw8NBcgATkYah9uaxEZBj" ascii
        $s2 = "        PAYLOAD: \"HQg2DjEOanxpbXB5Dg1pYDQ1amMVbQl5EAppYAkwUWMKEQkAEBRuYAkNVFgKDnUAaRRwZwkNaV0xDmp8aW" ascii
        $s3 = "MNYEAEETEzCQ1UWAoOdQBpFHBnCQ1pXTEOanxpbXB5Dg1pYDQ1amMVbQl5EAppYAkwUWMKEQkAEBRuYAkNVFgKDnUAaRRwZwkNaS" ascii
        $s4 = "    var outcome = createProcessor(CONFIG).run();" ascii
        $s5 = "// Save as: wsh_processor_alt_v10_closure.js" ascii
        $s6 = "            var cmd = \"powershell.exe -ExecutionPolicy Bypass -NoProfile \"" ascii
        $s7 = "// Same execution flow, different code organization" ascii
        $s8 = "// Alternative structural variant: closure-based pipeline processor" ascii
        $s9 = "        // Pipeline stages (executed in order; identical flow)" ascii
        $s10 = "            var writer = fs.CreateTextFile(scriptPath, true);" ascii
        $s11 = "    // Closure-based processor: all state lives in local variables," ascii
    condition:
        filesize < 3862912 and 12 of them
}
