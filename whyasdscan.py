#!/usr/bin/env python3
"""
whyasdscan — nmap-equivalent network scanner
Metasploit-style UI, pspy-style banner
Requires: scapy, root/sudo for SYN/UDP/raw scans
"""

import sys
import os
import socket
import struct
import time
import threading
import random
import ipaddress
import argparse
import signal
import select
import errno
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from collections import defaultdict

# ── Try scapy (needed for SYN/UDP/OS) ──────────────────────────────────────
try:
    from scapy.all import (
        IP, TCP, UDP, ICMP, ARP, Ether,
        sr1, srp, send, conf, RandShort
    )
    conf.verb = 0
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

# ── ANSI colors ──────────────────────────────────────────────────────────────
R  = '\033[0;31m'
G  = '\033[0;32m'
Y  = '\033[1;33m'
B  = '\033[0;34m'
C  = '\033[0;36m'
M  = '\033[0;35m'
W  = '\033[1;37m'
GR = '\033[0;90m'
DIM= '\033[2m'
BO = '\033[1m'
RST= '\033[0m'

VERSION = "2.0.0"
IS_ROOT = (os.geteuid() == 0)

# ── Service database (1000+ ports like nmap) ─────────────────────────────────
SERVICES = {
    1:"tcpmux",7:"echo",9:"discard",11:"systat",13:"daytime",
    17:"qotd",19:"chargen",20:"ftp-data",21:"ftp",22:"ssh",
    23:"telnet",25:"smtp",26:"rsftp",37:"time",42:"nameserver",
    43:"nicname",49:"tacacs",53:"domain",67:"dhcps",68:"dhcpc",
    69:"tftp",70:"gopher",79:"finger",80:"http",81:"hosts2-ns",
    82:"xfer",83:"mit-ml-dev",84:"ctf",85:"mit-ml-dev",87:"any-pri-term",
    88:"kerberos-sec",89:"su-mit-tg",90:"dnsix",99:"metagram",
    100:"newacct",106:"pop3pw",109:"pop2",110:"pop3",111:"rpcbind",
    113:"ident",119:"nntp",123:"ntp",135:"msrpc",137:"netbios-ns",
    138:"netbios-dgm",139:"netbios-ssn",143:"imap",144:"uma",
    146:"iso-tp0",161:"snmp",162:"snmptrap",163:"cmip-man",
    164:"cmip-agent",174:"mailq",177:"xdmcp",179:"bgp",
    199:"smux",211:"914c-g",212:"anet",213:"ipx",220:"imap3",
    246:"dsp3270",389:"ldap",427:"svrloc",443:"https",444:"snpp",
    445:"microsoft-ds",458:"appleqtc",465:"smtps",
    481:"dvs",497:"retrospect",500:"isakmp",514:"shell",
    515:"printer",524:"ncp",541:"uucp-rlogin",543:"klogin",
    544:"kshell",545:"ekshell",548:"afp",554:"rtsp",
    556:"remotefs",563:"snews",587:"submission",593:"http-rpc-epmap",
    625:"apple-xsrvr-admin",626:"imap2",631:"ipp",636:"ldapssl",
    646:"ldp",648:"rrp",666:"mdqs",667:"disclose",668:"mecomm",
    669:"meregister",700:"necp",701:"lmp",702:"iris-beep",
    706:"silc",711:"cisco-tdp",712:"tbrpf",720:"queuedss",
    729:"netviewdm1",730:"netviewdm2",731:"netviewdm3",
    741:"netgw",742:"netrcs",744:"flexlm",747:"fujitsu-dev",
    748:"ris-cm",749:"kerberos-adm",750:"rfile",751:"pump",
    752:"qrh",753:"rrh",754:"tell",758:"nlogin",759:"con",
    760:"ns",761:"rxe",762:"quotad",763:"cycleserv",
    764:"omserv",765:"webster",767:"phonebook",769:"vid",
    770:"cadlock",771:"rtip",772:"cycleserv2",773:"submit",
    774:"rpasswd",775:"entomb",776:"wpages",
    777:"multiling-http",780:"wpgs",800:"mdbs-daemon",
    801:"device",802:"mbap-s",
    808:"ccproxy-http",843:"flashpolicy",873:"rsync",
    880:"imap4-ssl",888:"accessbuilder",898:"sun-manageconsole",
    900:"omginitialrefs",901:"samba-swat",902:"vmware-auth",
    903:"vmware-idisk",911:"xact-backup",912:"vmware-auth",
    981:"softdep",987:"unknown",990:"ftps",991:"nas",
    992:"telnets",993:"imaps",995:"pop3s",
    999:"garcon",1000:"cadlock2",1001:"webpush",
    1008:"unknown",1009:"unknown",1010:"surf",
    1011:"unknown",1021:"exp1",1022:"exp2",
    1023:"netvenuechat",1024:"kdm",1025:"NFS-or-IIS",
    1026:"LSA-or-nterm",1027:"IIS",1028:"unknown",
    1029:"ms-lsa",1030:"iad1",1031:"iad2",1032:"iad3",
    1033:"netinfo-local",1034:"zincite-a",1035:"multidropper",
    1036:"nsstp",1037:"ams",1038:"mtqp",1039:"sbl",
    1040:"netsaint",1041:"danf-ak2",1042:"afrog",
    1043:"boinc-client",1044:"dcutility",1045:"fpitp",
    1046:"wfremotertm",1047:"neod1",1048:"neod2",
    1049:"td-postman",1050:"java-or-OTGfileshare",
    1051:"optika-emedia",1052:"ddt",1053:"remote-as",
    1054:"brvread",1055:"ansyslmd",1056:"vfo",
    1057:"startron",1058:"nim",1059:"nimreg",
    1060:"polestar",1061:"kiosk",1062:"veracity",
    1063:"kyoceranetdev",1064:"jstel",1065:"syscomlan",
    1066:"fpo-fns",1067:"instl-boots",1068:"instl-bootc",
    1069:"cognex-insight",1070:"gmrupdateserv",
    1071:"bsquare-voip",1072:"cardax",1073:"bridgecontrol",
    1074:"warmspotMgmt",1075:"rdrmshc",1076:"sns-credit",
    1077:"imgames",1078:"econnectd",1079:"asprovatalk",
    1080:"socks",1081:"pvuniwien",1082:"amt-esd-prot",
    1083:"ansoft-lm-1",1084:"ansoft-lm-2",1085:"webobjects",
    1086:"cplscrambler-lg",1087:"cplscrambler-in",
    1088:"cplscrambler-al",1089:"ff-annunc",1090:"ff-fms",
    1091:"ff-sm",1092:"obrpd",1093:"proofd",
    1094:"rootd",1095:"nicelink",1096:"cnrprotocol",
    1097:"sunclustermgr",1098:"rmiactivation",
    1099:"rmiregistry",1100:"mctp",
    1102:"adobeserver-1",1104:"xrl",1105:"ftranhc",
    1106:"isoipsigport-1",1107:"isoipsigport-2",
    1108:"ratio-adp",1110:"nfsd-status",
    1111:"lmsocialserver",1112:"msql",
    1113:"ltp-deepspace",1114:"mini-sql",
    1117:"ardus-mtrns",1119:"bnetgame",1121:"hpvmmcontrol",
    1122:"hpvmmagent",1123:"hpvmmdata",1124:"hpvroom",
    1126:"hpvwinas",1130:"casp",1131:"caspssl",
    1132:"kvm-via-ip",1137:"trim",1138:"encrypted-admin",
    1141:"mxomss",1145:"x9-icue",1147:"capioverlan",
    1148:"elfiq-repl",1149:"bvtsonar",1151:"unizensus",
    1152:"winpoplanmess",1154:"resacommunity",
    1163:"sddp",1164:"qsm-proxy",1165:"qsm-gui",
    1166:"qsm-remote",1169:"tripwire",
    1174:"fnet-remote-ui",1175:"dossier",
    1183:"llsurfup-http",1184:"llsurfup-https",
    1185:"catchpole",1186:"mysql-cluster",1187:"alias",
    1192:"caids-sensor",1198:"cajo-discovery",
    1199:"dmidi",1201:"scalable-sql",
    1213:"mpc-lifenet",1214:"fasttrack",
    1215:"scanstat-1",1216:"etebac5",1217:"hpss-ndapi",
    1218:"aeroflight-ads",1233:"univ-appserver",
    1234:"hotline",1236:"bvcontrol",1244:"isbconference1",
    1247:"visionpyramid",1248:"hermes",
    1259:"opennl-voice",1271:"excw",1272:"cspmlockmgr",
    1277:"miva-mqs",1287:"routematch",1296:"dproxy",
    1300:"h323hostcallsc",1301:"ci3-software-1",
    1309:"jtag-server",1310:"husky",1311:"rxmon",
    1322:"novation",1328:"ewall",1334:"writesrv",
    1352:"lotusnotes",1417:"timbuktu-srv1",
    1418:"timbuktu-srv2",1419:"timbuktu-srv3",
    1420:"timbuktu-srv4",1431:"rgtp",
    1433:"ms-sql-s",1434:"ms-sql-m",1443:"ies-lm",
    1455:"esl-lm",1461:"ibm-wrless-lan",1494:"citrix-ica",
    1500:"vlsi-lm",1501:"saiscm",1503:"imtc-mcs",
    1521:"oracle",1524:"ingreslock",
    1533:"virtual-places",1556:"veritas-pbx",
    1583:"simco",1594:"sixtrak",1600:"issd",
    1641:"invision",1658:"sixnetudr",1666:"netview-aix-6",
    1687:"nsjtp-ctrl",1688:"nsjtp-data",1700:"mps-raft",
    1717:"fj-hdnet",1718:"h225gatedisc",1719:"h225gatestat",
    1720:"h323q931",1721:"caicci",1723:"pptp",
    1755:"ms-streaming",1761:"landesk-rc",1782:"hp-hcip-gwy",
    1783:"unknown",1801:"msmq",1805:"enl-name",
    1812:"radius",1813:"radacct",1839:"netopia-vo1",
    1840:"netopia-vo2",1862:"mysql-cm-agent",
    1863:"msnp",1864:"paradym-31port",1875:"westell-stats",
    1900:"upnp",1914:"elm-momentum",1935:"rtmp",
    1947:"sentinelsrm",1971:"netopia-vo3",
    1972:"ldap-id",1974:"drp",1984:"bigbrother",
    1998:"x25-svc-port",1999:"tcp-id-port",
    2000:"cisco-sccp",2001:"dc",2002:"globe",
    2003:"finger",2004:"mailbox",2005:"deslogin",
    2006:"invokator",2007:"dectalk",2008:"conf",
    2009:"news",2010:"search",2011:"raid-cc",
    2012:"ttyinfo",2013:"raid-am",2014:"troff",
    2015:"cypress",2016:"bootserver",2017:"cypress-stat",
    2018:"terminaldb",2019:"whosockami",2020:"xinupageserver",
    2021:"servexec",2022:"down",2023:"xinuexpansion3",
    2024:"xinuexpansion4",2025:"ellpack",2026:"scrabble",
    2027:"shadowserver",2028:"submitserver",
    2029:"hsrpv6",2030:"device2",2033:"glogger",
    2034:"scoremgr",2035:"imsldoc",2038:"objectmanager",
    2040:"lam",2041:"interbase",2042:"isis",
    2043:"isis-bcast",2044:"rimsl",2045:"cdfunc",
    2046:"sdfunc",2047:"dls",2048:"dls-monitor",
    2049:"nfs",2065:"dlsrpn",2068:"advocentkvm",
    2099:"h2250-annex-g",2100:"amiganetfs",
    2103:"zephyr-clt",2105:"minipay",
    2106:"ekshell",2107:"msmq-mgmt",
    2111:"kx",2119:"gsigatekeeper",2121:"ccproxy-ftp",
    2126:"pktcable-cops",2135:"gris",
    2144:"lv-ffx",2160:"apc-2160",2161:"apc-agent",
    2170:"eyetv",2179:"vmrdp",2190:"tivoconnect",
    2191:"tvbus",2196:"unknown",2200:"ici",
    2222:"EtherNetIP-1",2251:"dif-port",
    2260:"apc-2260",2288:"netml",
    2301:"compaqdiag",2323:"3d-nfsd",
    2381:"compaq-https",2382:"ms-olap3",
    2383:"ms-olap4",2393:"ms-olap1",
    2394:"ms-olap2",2399:"fmpro-fdal",
    2401:"cvspserver",2492:"groove",
    2500:"rtsserv",2522:"windb",
    2525:"ms-v-worlds",2557:"nicetec-nmsvc",
    2601:"zebra",2602:"ripd",2604:"ospfd",
    2605:"bgpd",2607:"connection",2638:"sybase",
    2701:"sms-rcinfo",2702:"sms-xfer",
    2703:"sms-chat",2704:"sms-remctrl",
    2869:"icslap",2967:"symantec-av",
    3000:"hbci",3001:"redwood-broker",
    3005:"geniuslm",3006:"deslogind",
    3011:"trusted-web",3013:"gilatskysurfer",
    3017:"event_listener",3030:"arepa-cas",
    3052:"powerchute",3071:"csd-mgmt-port",
    3077:"orbix-loc-ssl",3128:"squid-http",
    3168:"poweronnud",3211:"avsecuremgmt",
    3220:"xnm-ssl",3221:"xnm-clear-text",
    3260:"iscsi",3261:"winshadow-hd",
    3268:"globalcatLDAP",3269:"globalcatLDAPssl",
    3283:"net-assistant",3300:"ceph",
    3306:"mysql",3322:"active-net",3323:"active-net",
    3324:"active-net",3325:"active-net",
    3333:"dec-notes",3351:"btrieve",
    3367:"satvid-datalnk",3369:"satvid-datalnk",
    3370:"satvid-datalnk",3371:"satvid-datalnk",
    3372:"msdtc",3374:"cluster-disc",
    3389:"ms-wbt-server",3404:"unknown",
    3476:"nppmp",3493:"nut",3517:"802-11-iapp",
    3527:"belarc-http",3546:"unknown",
    3551:"apcupsd",3580:"nati-svrloc",
    3659:"apple-sasl",3689:"rendezvous",
    3690:"svn",3703:"adobeserver-3",
    3737:"xpanel",3766:"sitewatch-s",
    3784:"bfd-control",3800:"pwgpsi",
    3801:"ibm-mgr",3809:"apocd",
    3814:"neto-wol-server",3826:"wormux",
    3827:"netmpi",3828:"neteh",
    3851:"spectralink-net",3869:"ovsam-mgmt",
    3900:"udt-os",3945:"emcads",
    3971:"lanrevserver",3984:"mapper-nodemgr",
    3985:"mapper-mapethd",3986:"mapper-ws-ethd",
    3995:"iss-mgmt-ssl",3998:"dnx",
    4000:"terabase",4001:"newoak",
    4002:"pxc-spvr-ft",4003:"pxc-splr-ft",
    4004:"pxc-roid",4005:"pxc-pin",
    4006:"pxc-spvr",4007:"pxc-splr",
    4008:"netcheque",4009:"chimera-hwm",
    4010:"samsung-unidex",4011:"altserviceboot",
    4012:"pda-gate",4013:"acl-manager",
    4014:"taiclock",4015:"talarian-mcast1",
    4016:"talarian-mcast2",4017:"talarian-mcast3",
    4018:"talarian-mcast4",4019:"talarian-mcast5",
    4045:"lockd",4111:"xgrid",4125:"rww",
    4129:"nuauth",4224:"unknown",
    4242:"vrml-multi-use",4279:"vrml-multi-use",
    4321:"rwhois",4343:"unicall",
    4443:"pharos",4444:"krb524",
    4445:"upnotifyp",4446:"n1-fwp",
    4449:"privatewire",4550:"gds-adppiw-db",
    4567:"tram",4662:"edonkey",
    4848:"app-server-https",4899:"radmin",
    4900:"hfcs",4998:"maybe-veritas",
    5000:"upnp",5001:"commplex-link",
    5002:"rfe",5003:"filemaker",
    5004:"avt-profile-1",5009:"airport-admin",
    5030:"surfpass",5033:"jtnetd-server",
    5050:"mmcc",5051:"ida-agent",
    5054:"rlm-admin",5060:"sip",
    5061:"sip-tls",5080:"onscreen",
    5087:"biotic",5100:"admd",
    5101:"admdog",5102:"admeng",
    5120:"barracuda-bbs",5190:"aol",
    5200:"targus-getdata",5214:"unknown",
    5221:"unknown",5222:"xmpp-client",
    5225:"hp-server",5226:"hp-status",
    5269:"xmpp-server",5280:"xmpp-bosh",
    5298:"presence",5357:"wsdapi",
    5405:"pcduo",5414:"statusd",
    5431:"park-agent",5432:"postgresql",
    5440:"unknown",5500:"hotline",
    5510:"secureidprop",5544:"unknown",
    5550:"sdadmind",5555:"freeciv",
    5560:"isqlplus",5566:"westec-connect",
    5631:"pcanywheredata",5632:"pcanywherestat",
    5666:"nrpe",5679:"activesync",
    5718:"dpm",5730:"uniport",
    5800:"vnc-http",5801:"vnc-http-1",
    5802:"vnc-http-2",5900:"vnc",
    5901:"vnc-1",5902:"vnc-2",
    5903:"vnc-3",5904:"vnc-4",
    5906:"unknown",5907:"unknown",
    5910:"cm",5911:"cpdlc",
    5915:"unknown",5922:"unknown",
    5925:"unknown",5950:"unknown",
    5952:"unknown",5959:"unknown",
    5960:"unknown",5961:"unknown",
    5962:"unknown",5963:"indy",
    5987:"wbem-rmi",5988:"wbem-http",
    5989:"wbem-https",5998:"ncd-diag",
    5999:"ncd-conf",6000:"X11",
    6001:"X11:1",6002:"X11:2",
    6003:"X11:3",6004:"X11:4",
    6005:"X11:5",6006:"X11:6",
    6007:"X11:7",6009:"X11:9",
    6025:"x11",6059:"X11:59",
    6100:"synchronet-db",6101:"synchronet-rtc",
    6106:"isdninfo",6112:"dtspc",
    6123:"backup-express",6129:"dameware",
    6156:"unknown",6346:"gnutella",
    6347:"gnutella",6389:"clariion-evr01",
    6443:"sun-sr-https",6481:"servicetags",
    6502:"netop-rc",6543:"mythtv",
    6547:"powerchuteplus",6548:"powerchuteplus",
    6549:"powerchuteplus",6550:"fg-sysupdate",
    6551:"unknown",6558:"xdsxdm",
    6566:"sane-port",6580:"parsec-master",
    6646:"unknown",6666:"irc",
    6667:"irc",6668:"irc",
    6669:"irc",6689:"tsa",
    6692:"unknown",6699:"napster",
    6779:"unknown",6788:"smc-http",
    6789:"radg",6792:"unknown",
    6839:"unknown",6881:"bittorrent-tracker",
    6901:"jetform",6969:"acmsoda",
    7000:"afs3-fileserver",7001:"afs3-callback",
    7002:"afs3-prserver",7004:"afs3-kaserver",
    7007:"afs3-bos",7019:"doceri-ctl",
    7025:"vmsvc-2",7070:"realserver",
    7100:"font-service",7103:"unknown",
    7106:"unknown",7200:"fodms",
    7201:"dlip",7402:"rtps-dd-mt",
    7435:"unknown",7443:"oracleas-https",
    7496:"unknown",7512:"unknown",
    7625:"unknown",7627:"soap-http",
    7676:"imqbrokerd",7741:"scriptview",
    7777:"cbt",7778:"interwise",
    7800:"unknown",7911:"unknown",
    7920:"unknown",7921:"unknown",
    7937:"nsrexecd",7938:"lgtomapper",
    7999:"irdmi2",8000:"http-alt",
    8001:"vcom-tunnel",8002:"teradataordbms",
    8007:"ajp12",8008:"http",
    8009:"ajp13",8010:"xmpp",
    8011:"unknown",8021:"ftp-proxy",
    8022:"oa-system",8031:"unknown",
    8042:"fs-agent",8045:"unknown",
    8080:"http-proxy",8081:"blackice-icecap",
    8082:"blackice-alerts",8083:"us-srv",
    8084:"unknown",8085:"unknown",
    8086:"d-s-n",8087:"simplifymedia",
    8088:"radan-http",8089:"unknown",
    8090:"unknown",8093:"unknown",
    8099:"unknown",8180:"unknown",
    8181:"intermapper",8192:"sophos",
    8193:"sophos",8194:"sophos",
    8200:"trivnet1",8201:"trivnet2",
    8222:"unknown",8243:"unknown",
    8280:"unknown",8281:"unknown",
    8291:"unknown",8333:"bitcoin",
    8383:"m2mservices",8400:"cvd",
    8402:"abarsd",8443:"https-alt",
    8500:"fmtp",8600:"asterix",
    8649:"unknown",8651:"unknown",
    8652:"unknown",8654:"unknown",
    8701:"unknown",8800:"sunwebadmin",
    8873:"dxi-api",8888:"ddi-tcp-1",
    8899:"ospf-lite",8994:"unknown",
    9000:"cslistener",9001:"etlservicemgr",
    9002:"dynamid",9003:"unknown",
    9009:"pichat",9010:"sdr",
    9011:"unknown",9040:"tor-trans",
    9050:"tor-socks",9071:"unknown",
    9080:"glrpc",9081:"unknown",
    9090:"zeus-admin",9091:"xmltec-xmlmail",
    9099:"unknown",9100:"jetdirect",
    9101:"jetdirect",9102:"jetdirect",
    9103:"jetdirect",9110:"unknown",
    9111:"DragonIDSConsole",9200:"wap-wsp",
    9207:"wap-vcal-s",9220:"unknown",
    9290:"unknown",9415:"unknown",
    9418:"git",9485:"unknown",
    9500:"ismserver",9502:"unknown",
    9503:"unknown",9535:"mngsuite",
    9575:"unknown",9593:"cba8",
    9594:"msgsys",9595:"pds",
    9618:"condor",9666:"unknown",
    9876:"sd",9877:"x510",
    9898:"monkeycom",9900:"iua",
    9917:"unknown",9929:"nping-echo",
    9943:"unknown",9944:"unknown",
    9968:"unknown",9998:"distinct32",
    9999:"abyss",10000:"ndmp",
    10001:"scp-config",10002:"documentum",
    10003:"documentum-s",10004:"emcrmirccd",
    10009:"unknown",10010:"rxapi",
    10012:"unknown",10024:"unknown",
    10025:"unknown",10082:"unknown",
    10180:"unknown",10215:"unknown",
    10243:"unknown",10566:"unknown",
    10616:"unknown",10617:"unknown",
    10621:"unknown",10626:"unknown",
    10628:"unknown",10629:"unknown",
    10778:"unknown",11110:"unknown",
    11967:"unknown",12000:"cce4x",
    12174:"unknown",12265:"unknown",
    12345:"netbus",13456:"unknown",
    13722:"netbackup",13782:"netbackup",
    13783:"netbackup",14000:"scotty-ft",
    14238:"unknown",14441:"unknown",
    14442:"unknown",15000:"hydap",
    15002:"onep-tls",15003:"unknown",
    15004:"unknown",15660:"bex-xr",
    15742:"unknown",16000:"fmsas",
    16001:"unknown",16012:"unknown",
    16016:"unknown",16018:"unknown",
    16080:"osxwebadmin",16113:"unknown",
    16992:"amt-soap-http",16993:"amt-soap-https",
    17877:"unknown",17988:"unknown",
    18040:"unknown",18101:"unknown",
    18988:"unknown",19101:"unknown",
    19283:"unknown",19315:"unknown",
    19350:"unknown",19780:"unknown",
    19801:"unknown",19842:"unknown",
    20000:"dnp",20005:"btx",
    20031:"unknown",20221:"unknown",
    20222:"unknown",20828:"unknown",
    21571:"unknown",22939:"unknown",
    23502:"unknown",24444:"unknown",
    24800:"unknown",25734:"unknown",
    25735:"unknown",26214:"unknown",
    27000:"flexlm0",27017:"mongod",
    27352:"unknown",27353:"unknown",
    27355:"unknown",27356:"unknown",
    27715:"unknown",28201:"unknown",
    30000:"ndmps",30718:"unknown",
    30951:"unknown",31038:"unknown",
    31337:"BackOrifice",32768:"filenet-tms",
    32769:"filenet-rpc",32770:"sometimes-rpc3",
    32771:"sometimes-rpc5",32772:"sometimes-rpc7",
    32773:"sometimes-rpc9",32774:"sometimes-rpc11",
    32775:"sometimes-rpc13",32776:"sometimes-rpc15",
    32777:"sometimes-rpc17",32778:"sometimes-rpc19",
    32779:"sometimes-rpc21",32780:"sometimes-rpc23",
    32781:"sometimes-rpc25",32782:"sometimes-rpc27",
    32783:"sometimes-rpc29",32784:"sometimes-rpc31",
    32785:"sometimes-rpc33",33354:"unknown",
    33899:"unknown",34571:"unknown",
    34572:"unknown",34573:"unknown",
    35500:"unknown",38292:"landesk-cba",
    40193:"unknown",40911:"unknown",
    41511:"unknown",42510:"caerpc",
    44176:"unknown",44442:"coldfusion-auth",
    44443:"coldfusion",44501:"unknown",
    45100:"unknown",48080:"unknown",
    49152:"unknown",49153:"unknown",
    49154:"unknown",49155:"unknown",
    49156:"unknown",49157:"unknown",
    49158:"unknown",49159:"unknown",
    49160:"unknown",49161:"unknown",
    49163:"unknown",49165:"unknown",
    49167:"unknown",49175:"unknown",
    49176:"unknown",49400:"compaqdiag",
    49999:"unknown",50000:"ibm-db2",
    50001:"ibm-db2",50002:"iiimsf",
    50003:"unknown",50006:"unknown",
    50300:"unknown",50389:"unknown",
    50500:"unknown",50636:"unknown",
    50800:"unknown",51103:"unknown",
    51493:"unknown",52673:"unknown",
    52822:"unknown",52848:"unknown",
    52869:"unknown",54045:"unknown",
    54328:"unknown",55055:"unknown",
    55056:"unknown",55555:"unknown",
    55600:"unknown",56737:"unknown",
    56738:"unknown",57294:"unknown",
    57797:"unknown",58080:"unknown",
    60020:"unknown",60443:"unknown",
    61532:"unknown",61900:"unknown",
    62078:"iphone-sync",63331:"unknown",
    64623:"unknown",64680:"unknown",
    65000:"unknown",65129:"unknown",
    65389:"unknown",
}

TOP_100 = [
    7,9,13,21,22,23,25,26,37,53,79,80,81,88,106,110,111,113,
    119,135,139,143,144,179,199,389,427,443,444,445,465,513,514,
    515,543,544,548,554,587,631,646,873,990,993,995,1025,1026,
    1027,1028,1029,1110,1433,1720,1723,1755,1900,2000,2001,2049,
    2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,
    5101,5190,5357,5432,5631,5666,5800,5900,6000,6001,6646,7070,
    8000,8008,8009,8080,8081,8443,8888,9100,9999,10000,32768,
    49152,49153,49154,49155,49156,49157,
]

TOP_1000 = sorted(list(SERVICES.keys()))[:1000]

# ── Banner animation ──────────────────────────────────────────────────────────
def animate_str(s, delay=0.008, color=G):
    for ch in s:
        sys.stdout.write(color + ch + RST)
        sys.stdout.flush()
        time.sleep(delay)
    print()

def show_banner():
    os.system('clear' if os.name == 'posix' else 'cls')
    logo = [
        (R, "  ██╗    ██╗██╗  ██╗██╗   ██╗ █████╗ ███████╗██████╗ "),
        (R, "  ██║    ██║██║  ██║╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗"),
        (Y, "  ██║ █╗ ██║███████║ ╚████╔╝ ███████║███████╗██║  ██║"),
        (Y, "  ██║███╗██║██╔══██║  ╚██╔╝  ██╔══██║╚════██║██║  ██║"),
        (W, "  ╚███╔███╔╝██║  ██║   ██║   ██║  ██║███████║██████╔╝"),
        (W, "   ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═════╝ "),
    ]
    for color, line in logo:
        print(color + line + RST)
        time.sleep(0.04)

    print()
    print(GR + '─' * 58 + RST)
    print()

    configs = [
        f"Config: Initializing whyasdscan v{VERSION} ...",
        f"Config: Loading {len(SERVICES)} service fingerprints ...",
        f"Config: Raw sockets: {'available (root)' if IS_ROOT else 'limited (no root)'}",
        f"Config: Scapy engine: {'loaded' if SCAPY_OK else 'not found — install: pip install scapy'}",
        f"Config: Watching interfaces: [eth0 lo wlan0] (auto-detect)",
    ]
    for line in configs:
        animate_str(line, delay=0.007, color=G)
        time.sleep(0.04)

    print(GR + '─' * 58 + RST)
    print()
    print(f"  {W}{BO}whyasdscan{RST} {GR}|{RST} {DIM}Network & Port Scanner — nmap-equivalent{RST}")
    print(f"  {GR}Version: {C}{VERSION}{RST}  {GR}Root: {G if IS_ROOT else R}{'yes' if IS_ROOT else 'no'}{RST}  {GR}Engine: scapy+raw{RST}")
    print()
    time.sleep(0.2)

# ── Target resolution ─────────────────────────────────────────────────────────
def resolve_targets(target_str):
    targets = []
    for t in target_str.split(','):
        t = t.strip()
        try:
            net = ipaddress.ip_network(t, strict=False)
            if net.num_addresses == 1:
                targets.append(str(net.network_address))
            else:
                for h in net.hosts():
                    targets.append(str(h))
        except ValueError:
            if '-' in t.split('.')[-1]:
                base = '.'.join(t.split('.')[:-1])
                rng = t.split('.')[-1]
                lo, hi = rng.split('-')
                for i in range(int(lo), int(hi)+1):
                    targets.append(f"{base}.{i}")
            else:
                try:
                    ip = socket.gethostbyname(t)
                    targets.append(ip)
                except socket.gaierror:
                    print(f"{R}[-]{RST} Cannot resolve: {t}")
    return targets

def parse_ports(spec):
    if spec == '-' or spec == 'all':
        return list(range(1, 65536))
    if spec == 'top100':
        return TOP_100[:]
    if spec == 'top1000':
        return TOP_1000[:]
    ports = set()
    for part in spec.split(','):
        part = part.strip()
        if '-' in part and not part.startswith('-'):
            lo, hi = part.split('-', 1)
            ports.update(range(int(lo), int(hi)+1))
        elif part.isdigit():
            ports.add(int(part))
    return sorted(ports)

# ── ICMP ping ─────────────────────────────────────────────────────────────────
def ping_icmp(host, timeout=1):
    """ICMP echo via scapy (root) or socket fallback"""
    if SCAPY_OK and IS_ROOT:
        try:
            pkt = IP(dst=host)/ICMP()
            resp = sr1(pkt, timeout=timeout, verbose=0)
            return resp is not None
        except Exception:
            pass
    # fallback: TCP SYN to port 80/443
    for port in (80, 443, 22):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            s.close()
            if result in (0, 111, errno.ECONNREFUSED):
                return True
        except Exception:
            pass
    return False

def arp_ping(host, timeout=2):
    """ARP ping (LAN only, requires root+scapy)"""
    if not SCAPY_OK or not IS_ROOT:
        return None
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=host),
                     timeout=timeout, verbose=0)
        if ans:
            return ans[0][1].hwsrc
        return None
    except Exception:
        return None

# ── TCP Connect scan ───────────────────────────────────────────────────────────
def tcp_connect(host, port, timeout=1):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((host, port))
        s.close()
        return result == 0
    except Exception:
        return False

# ── SYN scan (raw sockets via scapy) ─────────────────────────────────────────
def syn_scan(host, port, timeout=1):
    if not SCAPY_OK or not IS_ROOT:
        return tcp_connect(host, port, timeout)
    try:
        sport = random.randint(1024, 65535)
        pkt = IP(dst=host)/TCP(sport=sport, dport=port, flags='S')
        resp = sr1(pkt, timeout=timeout, verbose=0)
        if resp is None:
            return 'filtered'
        if resp.haslayer(TCP):
            flags = resp[TCP].flags
            if flags == 0x12:  # SYN-ACK
                # RST to close
                send(IP(dst=host)/TCP(sport=sport, dport=port, flags='R'), verbose=0)
                return 'open'
            elif flags == 0x14:  # RST-ACK
                return 'closed'
        if resp.haslayer(ICMP):
            return 'filtered'
        return 'filtered'
    except Exception:
        return tcp_connect(host, port, timeout)

# ── UDP scan ──────────────────────────────────────────────────────────────────
UDP_PAYLOADS = {
    53:  b'\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03',
    123: b'\x1b' + 47 * b'\x00',
    161: b'\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05+\x06\x01\x02\x01\x05\x00',
    500: b'\x00' * 28,
    1900: b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n',
}

def udp_scan(host, port, timeout=2):
    if not SCAPY_OK or not IS_ROOT:
        return 'open|filtered'
    try:
        payload = UDP_PAYLOADS.get(port, b'\x00' * 4)
        pkt = IP(dst=host)/UDP(dport=port)/payload
        resp = sr1(pkt, timeout=timeout, verbose=0)
        if resp is None:
            return 'open|filtered'
        if resp.haslayer(UDP):
            return 'open'
        if resp.haslayer(ICMP):
            t = resp[ICMP].type
            if t == 3:
                code = resp[ICMP].code
                if code in (1, 2, 9, 10, 13):
                    return 'filtered'
                return 'closed'
        return 'open|filtered'
    except Exception:
        return 'open|filtered'

# ── Banner grabbing ───────────────────────────────────────────────────────────
HTTP_PORTS = {80, 8080, 8000, 8008, 8081, 8082, 8083, 8084, 8085, 8088, 8180, 8888}
HTTPS_PORTS = {443, 8443, 4443, 9443}

def grab_banner(host, port, timeout=2):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))

        # Send probe
        if port in HTTP_PORTS:
            s.send(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
        elif port == 21:
            pass  # FTP sends banner automatically
        elif port == 22:
            pass  # SSH sends banner automatically
        elif port == 25 or port == 587:
            pass  # SMTP sends banner
        else:
            s.send(b'\r\n')

        banner = b''
        s.settimeout(timeout)
        while True:
            try:
                chunk = s.recv(1024)
                if not chunk:
                    break
                banner += chunk
                if len(banner) > 2048:
                    break
            except Exception:
                break
        s.close()

        text = banner.decode('utf-8', errors='replace').strip()
        # Extract server line from HTTP
        for line in text.splitlines():
            line = line.strip()
            if line.lower().startswith('server:'):
                return line[7:].strip()
        # First non-empty line
        for line in text.splitlines():
            line = line.strip()
            if line and len(line) < 200:
                return line
        return ''
    except Exception:
        return ''

# ── OS detection ──────────────────────────────────────────────────────────────
def detect_os_ttl(host, timeout=2):
    """TTL-based OS fingerprint"""
    try:
        if SCAPY_OK and IS_ROOT:
            pkt = IP(dst=host)/ICMP()
            resp = sr1(pkt, timeout=timeout, verbose=0)
            if resp and resp.haslayer(IP):
                ttl = resp[IP].ttl
            else:
                return None, None
        else:
            # Use socket ping fallback via system ping
            import subprocess
            out = subprocess.run(
                ['ping', '-c', '1', '-W', '1', host],
                capture_output=True, text=True, timeout=3
            )
            import re
            m = re.search(r'ttl=(\d+)', out.stdout, re.I)
            ttl = int(m.group(1)) if m else None

        if ttl is None:
            return None, None

        # Normalize TTL to common initial values
        if ttl <= 64:
            normalized = 64
            os_guess = "Linux/Unix"
        elif ttl <= 128:
            normalized = 128
            os_guess = "Windows"
        elif ttl <= 255:
            normalized = 255
            os_guess = "Cisco/Network"
        else:
            os_guess = "Unknown"
            normalized = ttl

        return os_guess, ttl
    except Exception:
        return None, None

def detect_os_tcp(host, open_ports, timeout=2):
    """TCP fingerprinting via scapy"""
    if not SCAPY_OK or not IS_ROOT or not open_ports:
        return None
    try:
        port = open_ports[0]
        sport = random.randint(1024, 65535)
        # Probe 1: SYN with options
        pkt = IP(dst=host)/TCP(
            sport=sport, dport=port, flags='S',
            options=[('MSS', 1460), ('SAckOK', ''), ('Timestamp', (0, 0)), ('NOP', None), ('WScale', 10)]
        )
        resp = sr1(pkt, timeout=timeout, verbose=0)
        if not resp or not resp.haslayer(TCP):
            return None

        # Reset
        send(IP(dst=host)/TCP(sport=sport, dport=port, flags='R'), verbose=0)

        win = resp[TCP].window
        opts = {o[0]: o[1] for o in resp[TCP].options if isinstance(o, tuple)}

        hints = []
        if win == 65535:
            hints.append("Windows-like window")
        elif win == 29200 or win == 5840:
            hints.append("Linux-like window")
        if 'Timestamp' in opts:
            hints.append("timestamp support")
        if 'WScale' in opts:
            hints.append("window scaling")

        return ', '.join(hints) if hints else None
    except Exception:
        return None

# ── Host scanner ─────────────────────────────────────────────────────────────
class ScanResult:
    def __init__(self, host):
        self.host = host
        self.hostname = ''
        self.state = 'up'
        self.mac = None
        self.os_guess = None
        self.ttl = None
        self.tcp_hints = None
        self.ports = []  # list of dicts: port, state, service, banner, protocol

def scan_host(host, ports, scan_type='sT', service_detect=False,
              os_detect=False, aggressive=False, timeout=1, udp=False):
    result = ScanResult(host)

    # Hostname
    try:
        result.hostname = socket.gethostbyaddr(host)[0]
    except Exception:
        result.hostname = ''

    # OS detect early (TTL)
    if os_detect or aggressive:
        result.os_guess, result.ttl = detect_os_ttl(host, timeout=max(timeout, 1))

    open_ports_list = []

    def check_port(port):
        if scan_type == 'sS' and IS_ROOT and SCAPY_OK:
            state = syn_scan(host, port, timeout)
            if state == True:
                state = 'open'
            elif state == False:
                state = 'closed'
        else:
            ok = tcp_connect(host, port, timeout)
            state = 'open' if ok else 'closed'

        if state != 'open' and state != 'open|filtered':
            return None

        service = SERVICES.get(port, 'unknown')
        banner = ''
        if (service_detect or aggressive) and state == 'open':
            banner = grab_banner(host, port, timeout=2)

        return {'port': port, 'state': state, 'service': service,
                'banner': banner, 'proto': 'tcp'}

    # TCP scan
    with ThreadPoolExecutor(max_workers=min(500, len(ports))) as ex:
        futs = {ex.submit(check_port, p): p for p in ports}
        for f in as_completed(futs):
            r = f.result()
            if r:
                result.ports.append(r)
                open_ports_list.append(r['port'])

    # UDP scan
    if udp:
        udp_ports = [53, 67, 68, 69, 123, 161, 162, 500, 514, 520,
                     1194, 1900, 4500, 5353]
        def check_udp(port):
            state = udp_scan(host, port, timeout=max(timeout, 2))
            if 'open' in state:
                service = SERVICES.get(port, 'unknown')
                return {'port': port, 'state': state, 'service': service,
                        'banner': '', 'proto': 'udp'}
            return None
        with ThreadPoolExecutor(max_workers=20) as ex:
            futs = {ex.submit(check_udp, p): p for p in udp_ports}
            for f in as_completed(futs):
                r = f.result()
                if r:
                    result.ports.append(r)

    # OS TCP hints (use open TCP ports)
    if (os_detect or aggressive) and open_ports_list:
        result.tcp_hints = detect_os_tcp(host, open_ports_list, timeout=max(timeout,1))

    # Sort ports
    result.ports.sort(key=lambda x: (x['proto'], x['port']))
    return result

# ── Output ────────────────────────────────────────────────────────────────────
def sep(char='─', n=70, color=GR):
    print(color + char * n + RST)

def dsep(n=70):
    print(C + '═' * n + RST)

def print_result(result, verbose=False):
    host_line = f"{C}{result.host}{RST}"
    if result.hostname:
        host_line += f" {GR}({result.hostname}){RST}"
    print(f"\n  {BO}{W}Scan report for {host_line}{RST}")

    if result.mac:
        print(f"  {GR}MAC Address: {W}{result.mac}{RST}")
    if result.os_guess:
        ttl_str = f" (TTL={result.ttl})" if result.ttl else ''
        print(f"  {GR}OS: {Y}{result.os_guess}{ttl_str}{RST}", end='')
        if result.tcp_hints:
            print(f"  {GR}TCP hints: {DIM}{result.tcp_hints}{RST}", end='')
        print()
    if result.state:
        print(f"  {GR}Host is {G}up{RST}")

    print()
    if not result.ports:
        print(f"  {GR}No open ports found.{RST}")
    else:
        print(f"  {BO}{GR}{'PORT':<14}{'STATE':<14}{'SERVICE':<18}{'VERSION / BANNER'}{RST}")
        sep()
        for p in result.ports:
            proto = p['proto']
            port_str = f"{p['port']}/{proto}"
            state = p['state']
            sc = G if state == 'open' else (Y if 'filtered' in state else R)
            svc = p['service']
            banner = p['banner'][:50] if p['banner'] else ''
            print(f"  {C}{port_str:<14}{RST}{sc}{state:<14}{RST}{W}{svc:<18}{RST}{GR}{banner}{RST}")

    open_n = sum(1 for p in result.ports if 'open' in p['state'])
    print(f"\n  {GR}{open_n} open port(s) | {len(result.ports)} total{RST}")

# ── Write output files ────────────────────────────────────────────────────────
def write_output(results, filepath, mode='normal'):
    with open(filepath, 'w') as f:
        f.write(f"# whyasdscan {VERSION} scan — {datetime.now()}\n")
        for r in results:
            f.write(f"Host: {r.host} ({r.hostname})\n")
            if r.os_guess:
                f.write(f"OS: {r.os_guess}\n")
            for p in r.ports:
                f.write(f"{p['port']}/{p['proto']} {p['state']} {p['service']} {p['banner']}\n")
            f.write('\n')

# ── Discovery phase ───────────────────────────────────────────────────────────
def discover_hosts(targets, timeout=1, verbose=False):
    alive = []
    lock = threading.Lock()

    def check(host):
        up = ping_icmp(host, timeout)
        if up:
            with lock:
                alive.append(host)
                print(f"\r{G}[+]{RST} {W}{host}{RST} {G}is up{RST}                           ")
        elif verbose:
            print(f"\r{GR}[-] {host} down{RST}                   ")

    print(f"\r  {GR}Checking {len(targets)} host(s)...{RST}", end='', flush=True)
    with ThreadPoolExecutor(max_workers=100) as ex:
        list(ex.map(check, targets))

    print(f"\r                                              \r", end='')
    return alive

# ── CLI argument parser (nmap-compatible) ─────────────────────────────────────
def build_parser():
    p = argparse.ArgumentParser(
        prog='whyasdscan',
        description=f'whyasdscan {VERSION} — nmap-equivalent scanner',
        add_help=False
    )
    p.add_argument('targets', nargs='*', help='Target host(s)/network(s)')

    # Scan types
    p.add_argument('-sS', action='store_true', help='SYN scan (root+scapy)')
    p.add_argument('-sT', action='store_true', help='TCP connect scan')
    p.add_argument('-sU', action='store_true', help='UDP scan')
    p.add_argument('-sn', '-sP', action='store_true', help='Ping scan only')
    p.add_argument('-sV', action='store_true', help='Service version detection')
    p.add_argument('-O', action='store_true', help='OS detection')
    p.add_argument('-A', action='store_true', help='Aggressive: OS+version+scripts')
    p.add_argument('-Pn', action='store_true', help='Skip host discovery')

    # Ports
    p.add_argument('-p', default=None, help='Port spec: 22,80,443 | 1-1024 | -')
    p.add_argument('-F', action='store_true', help='Fast scan (top 100 ports)')
    p.add_argument('--top-ports', type=int, default=None, metavar='N')
    p.add_argument('--open', action='store_true', help='Show only open ports')

    # Timing
    p.add_argument('-T0', action='store_true')
    p.add_argument('-T1', action='store_true')
    p.add_argument('-T2', action='store_true')
    p.add_argument('-T3', action='store_true')
    p.add_argument('-T4', action='store_true')
    p.add_argument('-T5', action='store_true')

    # Output
    p.add_argument('-oN', metavar='FILE', default=None)
    p.add_argument('-oG', metavar='FILE', default=None)
    p.add_argument('-v', action='store_true', help='Verbose')
    p.add_argument('-vv', action='store_true', help='Extra verbose')
    p.add_argument('-h', '--help', action='store_true')
    p.add_argument('-i', '--interactive', action='store_true')
    p.add_argument('--version', action='store_true')

    return p

# ── Help display ──────────────────────────────────────────────────────────────
def show_help():
    dsep()
    print(f"  {BO}{W}WHYASDSCAN — Network Scanner{RST}  {GR}v{VERSION}{RST}")
    dsep()
    print(f"""
  {Y}USAGE:{RST}
    {C}./whyasdscan.sh{RST} [options] {{target}}

  {Y}TARGET:{RST}
    {W}192.168.1.1{RST}          Single host
    {W}192.168.1.1-254{RST}      IP range
    {W}192.168.1.0/24{RST}       CIDR subnet
    {W}host1,host2{RST}          Comma-separated

  {Y}SCAN TYPES:{RST}
    {G}-sS{RST}   SYN scan      (root+scapy, stealth)
    {G}-sT{RST}   TCP connect   (no root needed)
    {G}-sU{RST}   UDP scan      (root+scapy)
    {G}-sn{RST}   Ping scan     (host discovery only)
    {G}-sV{RST}   Service/version detection
    {G}-O{RST}    OS detection  (TTL + TCP fingerprint)
    {G}-A{RST}    Aggressive    (OS+version+traceroute)
    {G}-Pn{RST}   Skip host discovery

  {Y}PORT SPEC:{RST}
    {G}-p{RST} 22,80,443        Specific ports
    {G}-p{RST} 1-1024           Range
    {G}-p-{RST}                 All 65535 ports
    {G}-F{RST}                  Top 100 ports
    {G}--top-ports{RST} N       Top N ports

  {Y}TIMING:{RST}
    {G}-T0{RST} Paranoid    {G}-T1{RST} Sneaky    {G}-T2{RST} Polite
    {G}-T3{RST} Normal      {G}-T4{RST} Aggressive  {G}-T5{RST} Insane

  {Y}OUTPUT:{RST}
    {G}-oN{RST} <file>   Normal output to file
    {G}-oG{RST} <file>   Greppable output
    {G}-v{RST}           Verbose
    {G}--open{RST}        Show open ports only

  {Y}EXAMPLES:{RST}
    {DIM}./whyasdscan.sh 192.168.1.1{RST}
    {DIM}./whyasdscan.sh -sS -p 1-1024 192.168.1.1{RST}
    {DIM}./whyasdscan.sh -A -T4 192.168.1.0/24{RST}
    {DIM}./whyasdscan.sh -sU -p 53,123,161 192.168.1.1{RST}
    {DIM}./whyasdscan.sh -p- -T5 192.168.1.1{RST}
    {DIM}./whyasdscan.sh -sn 10.0.0.0/24{RST}
    {DIM}./whyasdscan.sh -i{RST}  (interactive shell)
""")
    sep()

# ── Interactive Metasploit-style shell ────────────────────────────────────────
def interactive_shell():
    cfg = {
        'TARGET': '',
        'PORTS': 'top100',
        'SCAN_TYPE': 'sT',
        'TIMEOUT': 1,
        'THREADS': 100,
        'SVC': False,
        'OS': False,
        'UDP': False,
        'VERBOSE': False,
        'OUTPUT': '',
    }

    print(f"\n  {GR}Type {W}help{GR} for usage, {W}exit{GR} to quit.{RST}\n")

    while True:
        try:
            sys.stdout.write(f"\n{R}whyasdscan{RST} {W}>{RST} ")
            sys.stdout.flush()
            line = input().strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n\n  {GR}Goodbye.{RST}\n")
            sys.exit(0)

        if not line:
            continue

        parts = line.split()
        cmd = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ''
        rest = ' '.join(parts[2:]) if len(parts) > 2 else ''

        if cmd in ('exit', 'quit', 'q'):
            print(f"\n  {GR}Goodbye.{RST}\n")
            sys.exit(0)

        elif cmd == 'help':
            show_help()

        elif cmd == 'clear':
            os.system('clear')

        elif cmd == 'version':
            print(f"  whyasdscan {C}{VERSION}{RST}")

        elif cmd == 'set':
            key = args.upper()
            val = rest or (parts[2] if len(parts) > 2 else '')
            if key == 'TARGET':
                cfg['TARGET'] = val
                print(f"  {G}TARGET{RST} => {W}{val}{RST}")
            elif key == 'PORTS':
                cfg['PORTS'] = val
                print(f"  {G}PORTS{RST} => {W}{val}{RST}")
            elif key == 'TIMEOUT':
                cfg['TIMEOUT'] = float(val)
                print(f"  {G}TIMEOUT{RST} => {W}{val}{RST}")
            elif key == 'THREADS':
                cfg['THREADS'] = int(val)
                print(f"  {G}THREADS{RST} => {W}{val}{RST}")
            elif key == 'OUTPUT':
                cfg['OUTPUT'] = val
                print(f"  {G}OUTPUT{RST} => {W}{val}{RST}")
            else:
                print(f"  {Y}[!]{RST} Unknown option: {key}")

        elif cmd == 'use':
            mod = args.lower()
            if mod in ('sv', 'service', '-sv'):
                cfg['SVC'] = True
                print(f"  {G}[*]{RST} Service detection: ON")
            elif mod in ('o', 'os', '-o'):
                cfg['OS'] = True
                print(f"  {G}[*]{RST} OS detection: ON")
            elif mod in ('a', 'aggressive', '-a'):
                cfg['SVC'] = cfg['OS'] = True
                print(f"  {G}[*]{RST} Aggressive mode: ON")
            elif mod in ('su', 'udp', '-su'):
                cfg['UDP'] = True
                print(f"  {G}[*]{RST} UDP scan: ON")
            elif mod in ('ss', 'syn', '-ss'):
                cfg['SCAN_TYPE'] = 'sS'
                print(f"  {G}[*]{RST} SYN scan: ON {'(root available)' if IS_ROOT else '(no root — fallback to sT)'}")
            else:
                print(f"  {Y}[!]{RST} use sv | use O | use A | use sS | use sU")

        elif cmd == 'show':
            if args in ('options', 'info', ''):
                print(f"\n  {BO}{W}Module options:{RST}")
                sep()
                rows = [
                    ('TARGET',  cfg['TARGET'] or '<not set>', 'Host/network to scan'),
                    ('PORTS',   cfg['PORTS'],                  'Ports to scan'),
                    ('SCAN_TYPE', cfg['SCAN_TYPE'],            'Scan method (sT/sS)'),
                    ('TIMEOUT', str(cfg['TIMEOUT'])+'s',       'Per-port timeout'),
                    ('THREADS', str(cfg['THREADS']),           'Parallel threads'),
                    ('SVC',     str(cfg['SVC']),               'Service version detect'),
                    ('OS',      str(cfg['OS']),                'OS fingerprinting'),
                    ('UDP',     str(cfg['UDP']),               'UDP port scan'),
                    ('OUTPUT',  cfg['OUTPUT'] or '<none>',     'Output file'),
                ]
                print(f"  {C}{'Name':<12}  {'Value':<22} {'Description'}{RST}")
                sep()
                for name, val, desc in rows:
                    vc = Y if val not in ('False','<not set>','<none>') else GR
                    print(f"  {W}{name:<12}{RST}  {vc}{val:<22}{RST} {GR}{desc}{RST}")
                print()

        elif cmd in ('run', 'scan', 'execute', 'go'):
            if not cfg['TARGET']:
                print(f"  {R}[-]{RST} No target. Use: set TARGET <host/network>")
                continue
            do_scan(
                target=cfg['TARGET'],
                port_spec=cfg['PORTS'],
                scan_type=cfg['SCAN_TYPE'],
                service_detect=cfg['SVC'],
                os_detect=cfg['OS'],
                udp=cfg['UDP'],
                timeout=cfg['TIMEOUT'],
                verbose=cfg['VERBOSE'],
                output_file=cfg['OUTPUT'],
            )

        else:
            # Treat as: <target> [ports]
            if '.' in cmd or '/' in cmd or cmd[0].isdigit():
                cfg['TARGET'] = cmd
                if args:
                    cfg['PORTS'] = args
                do_scan(
                    target=cfg['TARGET'],
                    port_spec=cfg['PORTS'],
                    scan_type=cfg['SCAN_TYPE'],
                    service_detect=cfg['SVC'],
                    os_detect=cfg['OS'],
                    udp=cfg['UDP'],
                    timeout=cfg['TIMEOUT'],
                    verbose=cfg['VERBOSE'],
                    output_file=cfg['OUTPUT'],
                )
            else:
                print(f"  {Y}[!]{RST} Unknown command: {cmd}. Type 'help'.")

# ── Core scan entry point ─────────────────────────────────────────────────────
def do_scan(target, port_spec='top100', scan_type='sT',
            service_detect=False, os_detect=False, udp=False,
            timeout=1, verbose=False, output_file='', ping_only=False,
            skip_discovery=False):

    start = time.time()
    print()
    dsep()
    print(f"  {BO}{W}Starting whyasdscan {VERSION}{RST} {GR}at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RST}")
    dsep()
    print()

    # Resolve
    print(f"{C}[*]{RST} Resolving target: {C}{target}{RST}")
    targets = resolve_targets(target)
    if not targets:
        print(f"{R}[-]{RST} No valid targets.")
        return
    print(f"{C}[*]{RST} Targets: {G}{len(targets)}{RST} host(s)")

    # Discovery
    if skip_discovery:
        alive = targets
        print(f"{Y}[!]{RST} Skipping host discovery (-Pn)")
    elif ping_only or len(targets) > 1:
        print(f"\n{C}[*]{RST} {BO}Host Discovery{RST}")
        sep()
        alive = discover_hosts(targets, timeout=timeout, verbose=verbose)
        print(f"\n{G}[+]{RST} {G}{len(alive)}{RST} / {len(targets)} host(s) up")
    else:
        alive = targets

    if ping_only:
        elapsed = time.time() - start
        print()
        dsep()
        print(f"  {BO}{W}Done:{RST} {GR}{len(alive)} host(s) in {elapsed:.2f}s{RST}")
        dsep()
        return

    if not alive:
        print(f"\n{Y}[!]{RST} No live hosts — scanning anyway...")
        alive = targets

    # Ports
    ports = parse_ports(port_spec)
    print(f"\n{C}[*]{RST} Scanning {G}{len(alive)}{RST} host(s), {G}{len(ports)}{RST} port(s) [{scan_type}]")
    sep()

    results = []
    for host in alive:
        print(f"\n{C}[*]{RST} Scanning {C}{host}{RST}...")
        r = scan_host(
            host, ports,
            scan_type=scan_type,
            service_detect=service_detect,
            os_detect=os_detect,
            aggressive=(service_detect and os_detect),
            timeout=timeout,
            udp=udp,
        )
        print_result(r, verbose)
        results.append(r)

    elapsed = time.time() - start
    print()
    dsep()
    print(f"  {BO}{W}whyasdscan done:{RST} {GR}{len(alive)} host(s) scanned in {elapsed:.2f}s{RST}")
    dsep()

    if output_file:
        write_output(results, output_file)
        print(f"\n{G}[+]{RST} Output saved: {W}{output_file}{RST}")

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    signal.signal(signal.SIGINT, lambda s, f: (print(f"\n\n{Y}[!]{RST} Interrupted.\n"), sys.exit(130)))

    show_banner()

    parser = build_parser()
    args, unknown = parser.parse_known_args()

    if args.version:
        print(f"whyasdscan {VERSION}")
        sys.exit(0)

    if args.help or (not args.targets and not args.interactive):
        if not args.interactive:
            show_help() if args.help else None
            if not args.help:
                interactive_shell()
                return
        else:
            interactive_shell()
            return
        return

    if args.interactive:
        interactive_shell()
        return

    # Timing presets
    timeout = 1
    if args.T0: timeout = 5
    elif args.T1: timeout = 3
    elif args.T2: timeout = 2
    elif args.T3: timeout = 1
    elif args.T4: timeout = 0.5
    elif args.T5: timeout = 0.2

    # Port spec
    if args.p == '-':
        port_spec = '1-65535'
    elif args.p:
        port_spec = args.p
    elif args.F:
        port_spec = 'top100'
    elif args.top_ports:
        port_spec = f'top{args.top_ports}'
    else:
        port_spec = 'top1000'

    scan_type = 'sT'
    if args.sS:
        if IS_ROOT and SCAPY_OK:
            scan_type = 'sS'
        else:
            print(f"{Y}[!]{RST} SYN scan requires root + scapy. Using TCP connect.")
    
    service_detect = args.sV or args.A
    os_detect = args.O or args.A

    target = ','.join(args.targets)

    do_scan(
        target=target,
        port_spec=port_spec,
        scan_type=scan_type,
        service_detect=service_detect,
        os_detect=os_detect,
        udp=args.sU,
        timeout=timeout,
        verbose=args.v or args.vv,
        output_file=args.oN or args.oG or '',
        ping_only=args.sn,
        skip_discovery=args.Pn,
    )

if __name__ == '__main__':
    main()
