rule Sightlines_c2_5baf12f1_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign c2-5baf12f1"
        date = "2026-11-01"
        campaign = "c2-5baf12f1"
        family = "mirai"
        hash = "1744e3edef3747fbc31ae5b6aaa9c6592108b6ca7fe45ceb27b89baf9f84fc48"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/c2-5baf12f1.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "!(stream->flags & UV_HANDLE_BLOCKING_WRITES)" ascii
        $s1 = "/usr/bin/env -u SSH_TTY SSH_CONNECTION=test BASH_ENV=/root/.bashrc /bin/bash -c 'printf __TTY_GUARD_" ascii
        $s2 = "!(handle->flags & UV_HANDLE_UDP_PROCESSING)" ascii
        $s3 = "_ssh_cmd=${BASH_EXECUTION_STRING:-${ZSH_EXECUTION_STRING:-${SSH_ORIGINAL_COMMAND-}}}; _ssh_xfer_re='" ascii
        $s4 = "il2ban) || (command -v apt-get && apt-get install -y fail2ban)) && echo \"[DEFAULT]\\nmaxretry=3\\nbant" ascii
        $s5 = "/usr/bin/env SSH_TTY=/dev/pts/test SSH_CONNECTION=test BASH_ENV=/root/.bashrc /bin/bash -c 'printf _" ascii
        $s6 = "client side MAX_CONCURRENT_STREAMS reached, skip (%u)" ascii
        $s7 = "!uv__io_active(&handle->io_watcher, POLLIN | POLLOUT)" ascii
        $s8 = "cannot curl_ws_start_frame() with CURLWS_RAW_MODE enabled" ascii
        $s9 = "(stream->type == UV_TCP || stream->type == UV_NAMED_PIPE || stream->type == UV_TTY) && \"uv_write (un" ascii
        $s10 = "Authorization: %.*s4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s" ascii
        $s11 = "!uv__io_active(&stream->io_watcher, POLLIN | POLLOUT)" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 5308416 and 3 of them
}
