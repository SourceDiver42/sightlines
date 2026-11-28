rule Sightlines_tlsh_2c78adec_coinminer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-2c78adec"
        date = "2026-11-23"
        campaign = "tlsh-2c78adec"
        family = "coinminer"
        hash = "1d59e4230d5c3d74c4277358385f1406b0d722ce8f649c460ee0298b462e2fa0"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-2c78adec.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "    if cmake -S \"$WORK/xmrig\" -B \"$WORK/xmrig/build\" -DCMAKE_BUILD_TYPE=Release -DWITH_HWLOC=ON >/tm" ascii
        $s1 = "MEMK=$(awk '/^MemTotal:/{print $2}' /proc/meminfo 2>/dev/null || echo 0)" ascii
        $s2 = "  if command -v getconf >/dev/null 2>&1; then getconf _NPROCESSORS_ONLN 2>/dev/null && return; fi" ascii
        $s3 = "    git clone --depth 1 https://github.com/xmrig/xmrig.git \"$WORK/xmrig\" >/tmp/kx.clone.log 2>&1 || " ascii
        $s4 = "    INS=\"$PM -o DPkg::Lock::Timeout=120 -y install\"" ascii
        $s5 = "if ! mkdir -p \"$WORK\" 2>/dev/null; then WORK=\"/tmp/miners\"; mkdir -p \"$WORK\" 2>/dev/null; fi" ascii
        $s6 = "    BUILDPKGS=\"base-devel cmake libuv openssl hwloc screen git curl ca-certificates\" ;;" ascii
        $s7 = "  if [ -f \"$WORK/xmrig/CMakeLists.txt\" ]; then" ascii
        $s8 = "    BUILDPKGS=\"build-base cmake libuv-dev openssl-dev hwloc-dev screen git curl ca-certificates libc" ascii
        $s9 = "    BUILDPKGS=\"git gcc gcc-c++ make cmake libuv-devel libopenssl-devel hwloc-devel screen ca-certifi" ascii
        $s10 = "    BUILDPKGS=\"git gcc gcc-c++ make cmake libuv-devel openssl-devel hwloc-devel screen ca-certificat" ascii
        $s11 = "    BIN=$(command -v xmrig); say \"distro package: $BIN\"; ok distro-pkg" ascii
    condition:
        filesize < 1048576 and 12 of them
}
