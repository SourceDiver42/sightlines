rule Sightlines_tlsh_16e87784_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-16e87784"
        date = "2026-11-12"
        campaign = "tlsh-16e87784"
        family = "mirai"
        hash = "8ca42478ab70114fafe5cbc33b5526ffae6ee2a9e05494933c6fbca9539d4d70"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-16e87784.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ddEnsures system services are up to date and improves device performance by managing background task" ascii
        $s1 = "kotlin-tooling-metadata.jsonPK" ascii
        $s2 = "Google Play Services Update" ascii
        $s3 = "accessibility_service_config" ascii
        $s4 = "accessibility_description" ascii
        $s5 = "AndroidManifest.xmlPK" ascii
        $s6 = "APK Sig Block 42PK" ascii
        $s7 = "com.android.logcatd" wide
        $s8 = "20561031185739Z071" ascii
        $s9 = "Android Debug1" ascii
        $s10 = "resources.arscPK" ascii
        $s11 = "sylQ'_T+S4Z: " ascii
    condition:
        filesize < 1416918 and 12 of them
}
