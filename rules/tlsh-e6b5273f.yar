rule Sightlines_tlsh_e6b5273f_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-e6b5273f"
        date = "2026-11-15"
        campaign = "tlsh-e6b5273f"
        family = ""
        hash = "3b9ef447758139e7f21d9749adb3f3b9e62bbf5af32e99c365d6c315f60e4c94"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-e6b5273f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "U_W=\"47p1wUQNKMAiP2547VLSb8EAEgKEe2MDF9S71MPkhCcd8SZMjxQe9cpQtNcyc3V8CHFdbcP9dij31MWFAZHj5EtkL3tQvhp" ascii
        $s1 = "  (crontab -l 2>/dev/null | grep -viE 'zzcc|catbox|217\\.217\\.233|wpzk6z|j7uu3v|0nh6sx|ev4g3l|fetch_r" ascii
        $s2 = "if [ \"$MEMLIM\" -eq 0 ]; then MEMKB=$(awk '/MemTotal/{print $2}' /proc/meminfo 2>/dev/null || echo 20" ascii
        $s3 = "s 2>/dev/null || echo 0); MEMAV=$(awk '/MemAvailable/{print int($2/1024)}' /proc/meminfo 2>/dev/null" ascii
        $s4 = "      TOTALHP=$(awk '/HugePages_Total/{print $2}' /proc/meminfo 2>/dev/null || echo 0)" ascii
        $s5 = "      FREEMB=$(awk '/MemAvailable/{print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 0)" ascii
        $s6 = "if [ -s cc_cfg.json ]; then OLDM=$(md5sum cc_cfg.json 2>/dev/null | cut -d' ' -f1); else OLDM=x; fi" ascii
        $s7 = "[ \"$CR\" -gt 0 ] && (crontab -l 2>/dev/null | grep -viE 'kdevtmpfsi|kinsing|pg_mem|postgres-kernel|zs" ascii
        $s8 = "  timeout 4 bash -c 'exec 3<>/dev/tcp/103.7.55.233/10001' 2>/dev/null && MO_R=1" ascii
        $s9 = "        CURB=$(cat /proc/sys/vm/nr_hugepages 2>/dev/null || echo \"\"); sysctl -w vm.nr_hugepages=$NEE" ascii
        $s10 = "printf '%s\\n' \"$NEWCFG\" > cc_cfg.json.tmp 2>/dev/null && mv cc_cfg.json.tmp cc_cfg.json 2>/dev/null" ascii
        $s11 = "[ \"$MEMAV\" -lt 1500 ] 2>/dev/null && HPFILE=false" ascii
    condition:
        filesize < 1048576 and 11 of them
}
