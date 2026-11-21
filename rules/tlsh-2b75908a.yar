rule Sightlines_tlsh_2b75908a_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-2b75908a"
        date = "2026-11-19"
        campaign = "tlsh-2b75908a"
        family = ""
        hash = "5118c9241a7bb225bf4fbeb245aeb535c3fbe8f3b7a26e9e19cb728f9672e259"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-2b75908a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "               sendraw($IRC_cur_socket, \"PRIVMSG $printl :\\002Flood\\002: \".int((($bytes{icmp}+$bytes" ascii
        $s1 = "  socket(SOCK2, PF_INET, SOCK_DGRAM, 17) or $cp++;" ascii
        $s2 = "  $request .= \"Pragma: no-cache\\015\\012\" if ($main::http_no_cache);" ascii
        $s3 = "  #my $retornonick = &_get(\"http://websurvey.burstmedia.com/names.txt\");" ascii
        $s4 = "   my $IRC_socket = IO::Socket::INET->new(Proto=>\"tcp\", PeerAddr=>\"$servidor_con\", PeerPort=>$porta_" ascii
        $s5 = "    $sendsock = IO::Socket::INET->new(Listen=>1, LocalPort =>$porta, Proto => 'tcp') and $dcc_sel->a" ascii
        $s6 = "  socket(SOCK1, PF_INET, SOCK_RAW, 2) or $cp++;" ascii
        $s7 = "  socket(SOCK3, PF_INET, SOCK_RAW, 1) or $cp++;" ascii
        $s8 = "  socket(SOCK4, PF_INET, SOCK_RAW, 6) or $cp++;" ascii
        $s9 = "     sendraw(\"USER $ircname \".$IRC_socket->sockhost.\" $servidor_con :$realname\");" ascii
        $s10 = "  my $retornoident = &_get(\"http://www.minpop.com/sk12pack/idents.php\");" ascii
        $s11 = "               sendraw($IRC_cur_socket, \"PRIVMSG $printl :\\002Conectando-se em\\002: $host:$porta\");" ascii
    condition:
        filesize < 1048576 and 8 of them
}
