rule Sightlines_tlsh_d18e870b_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-d18e870b"
        date = "2026-11-15"
        campaign = "tlsh-d18e870b"
        family = ""
        hash = "499af8f6480ac2c7105e651f803d3611f38039a242e5ee22abf17318e096ea10"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-d18e870b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "DZamtmcr0MZUvlVDDnAMU59opdG4JP71S0IYozYBbXylBsHZ+s2bSdjZYTZbT0/oQZlpX2duAnYn9Ant3qLKQ9 weblogic@sjt-" ascii
        $s1 = "dnQ8TqVZZNFElrwYDHHtrzZOji7iMW0LuFDE/hkk2C5hLKD5BxmzCFZUi7BQXSgcCCwqTNe0V0QxnEbyjmePrgNVni6MOMqw+Xmf" ascii
        $s2 = "+ewWp8uBLPLUtH9zpt54OQI1ebBDe+BOZYHRrfCshsQ75moWA/TjO5S7IalrBGeUpXPOYlyDyAfhjy/5dG0EGA+oO3Sui+38CDT4" ascii
        $s3 = "echo \"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCcczUbb3KWRPOdPrZECTFvOnRmOYoq/EOcr34XcTBq2XkRAKa6W9XNuL" ascii
        $s4 = "ce\\|awk\\|sbin\\|WebLogic.sh\\|server\\|aux\\|httpd\\|sh\\|sbin' | grep ${s2:0:7} | awk '{print $2}' | xarg" ascii
        $s5 = "ce\\|awk\\|sbin\\|WebLogic.sh\\|server\\|aux\\|httpd\\|sh\\|sbin' | grep $s2 | awk '{print $2}' | xargs -I %" ascii
        $s6 = "ntr\\|nqscheduler\\|ps\\|sleep'| awk '{print $1}'| xargs -I % kill -9 %" ascii
        $s7 = "    ps aux | grep -v 'java\\|redis\\|weblogic\\|mongod\\|mysql\\|oracle\\|tomcat\\|grep\\|postgres\\|confluen" ascii
        $s8 = "killall /var/tmp/.system-python3.8-Updates/*" ascii
        $s9 = "ostgres\\|confluence\\|awk\\|sbin\\|WebLogic\\|server\\|aux\\|httpd\\|sh\\|pts\\|startNodeManage\\|nqsclusterco" ascii
        $s10 = "rm -rf /var/tmp/.system-python3.8-Updates/*" ascii
        $s11 = "killall /tmp/.system-python3.8-Updates/*" ascii
    condition:
        filesize < 1048576 and 12 of them
}
