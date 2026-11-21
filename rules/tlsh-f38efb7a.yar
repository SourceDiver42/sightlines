rule Sightlines_tlsh_f38efb7a_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f38efb7a"
        date = "2026-11-12"
        campaign = "tlsh-f38efb7a"
        family = ""
        hash = "18ab51b6e4d3bb914579a2e87d2f099997574f18b320cf5ab07602b5db6ab19f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-f38efb7a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "#GET_SOURCES_URL=$(cat /etc/apt/sources.list|grep ^deb|head -n 1|awk -F[/:] '{print $4}')" ascii
        $s1 = "LOCAL_CURL=$(curl -k https://127.0.0.1:${panelPort}/login 2>&1 |grep -i html)" ascii
        $s2 = "    #is_ssl=$($pyenv_path/pyenv/bin/python3.13.14 -c \"import ssl; print(ssl.OPENSSL_VERSION)\" 2>&1|g" ascii
        $s3 = "LOCAL_CURL=$(curl 127.0.0.1:${panelPort}/login 2>&1 |grep -i html)" ascii
        $s4 = "CN_YUM_URL=$(grep -E \"aliyun|163|tencent|tsinghua\" /etc/yum.repos.d/CentOS-Base.repo)" ascii
        $s5 = "qrencode -t ANSIUTF8 \"https://work.weixin.qq.com/kfid/kfc9072f0e29a53bd52\"" ascii
        $s6 = "WRONG_PATH_CHECK=$(grep -r \"centos/9/\" /etc/yum.repos.d/*.repo 2>/dev/null | grep -v \"9-stream\")" ascii
        $s7 = "MIRROR_CHECK=$(cat /etc/yum.repos.d/CentOS-Linux-AppStream.repo |grep \"[^#]mirror.centos.org\")" ascii
        $s8 = "NODE_CHECK=$(curl --connect-timeout 3 -m 3 2>/dev/null -w \"%{http_code} %{time_total}\" ${GET_SOURCES" ascii
        $s9 = "MIRROR_CHECK=$(grep -r \"[^#]mirror.centos.org\" /etc/yum.repos.d/CentOS-*.repo 2>/dev/null)" ascii
        $s10 = "GET_SOURCES_URL=$(cat /etc/apt/sources.list.d/ubuntu.sources|grep ^URIs:|head -n 1|sed -E 's|^[^ ]+ " ascii
        $s11 = "LIBCURL_VER=$(dpkg -l|grep libcurl4|awk '{print $3}')" ascii
    condition:
        filesize < 1048576 and 12 of them
}
