#!/bin/sh

##############################
# General settings
##############################
# "atm" for old-school DSL, "DOCSIS" for cable modem, or "other" for anything else
LINKTYPE="ethernet" 
WAN=eth1 # Change this to your WAN device name
LAN=eth0 # Change to your LAN device if you don't use veth/bridge, leave it alone if you use veth
DOWNRATE=90000 # Change this to about 80% of your download speed (in kbps)
UPRATE=45000 # Change this to your kbps upload speed
OH=44 # Number of bytes of Overhead on your line
PRESERVE_CONFIG_FILES="yes"  # Set to "yes" to preserve, "no" to ignore during sysupgrade

##############################
# Downstream shaping method
##############################
DOWNSHAPING_METHOD="ctinfo" # Options: "veth", "ctinfo", "lan"

## "ctinfo"  Uses connection tracking information to restore DSCP markings on incoming packets
## "veth" Utilizes a virtual Ethernet pair to control incoming traffic
## "lan" Applies traffic shaping directly on the LAN interface, (ideal) for environments with a single interface directed towards the LAN. 

##############################
# Veth-specific settings (only adjust if using the Veth setup)
##############################
LANBR=br-lan # LAN bridge interface name, only relevant if USEVETHDOWN is set to "yes"

##############################
# Performance settings
##############################

BWMAXRATIO=20 ## prevent ack floods by limiting download to at most
	      ## upload times this amount... ratio somewhere between
	      ## 10 and 20 probably optimal. we down-prioritize
	      ## certain ACKs to reduce the chance of a flood as well.

if [ $((DOWNRATE > UPRATE*BWMAXRATIO)) -eq 1 ]; then
    echo "We limit the downrate to at most $BWMAXRATIO times the upstream rate to ensure no upstream ACK floods occur which can cause game packet drops"
    DOWNRATE=$((BWMAXRATIO*UPRATE))
fi

## how many kbps of UDP upload and download do you need for your games across all gaming machines? 

## you can tune these yourself, but a good starting point is this formula. this script will not work for UPRATE less than about
## 600kbps or downrate less than about 1000kbps

GAMEUP=$((UPRATE*15/100+400))
GAMEDOWN=$((DOWNRATE*15/100+400))

## you can try setting GAMEUP and GAMEDOWN manually, some report this works well for CoD
#GAMEUP=400
#GAMEDOWN=800


##############################
# Qdisc selection
##############################

## Right now there are four possible leaf qdiscs: pfifo, red,
## fq_codel, or netem. If you use netem it's so you can intentionally
## add delay to your packets, set netemdelayms to the number of ms you
## want to add each direction. Our default is pfifo it is reported to
## be the best for use in the realtime queue

gameqdisc="pfifo"

#gameqdisc="netem"

##############################
# pfifo Qdisc Settings
##############################

# pfifo (Packet FIFO) is utilized for maintaining low latency and minimal packet loss,
# particularly suited for real-time applications like gaming. It operates by queuing packets
# in a first-in-first-out manner without any packet classification, ensuring fairness
# and simplicity in packet delivery.

PFIFOMIN=5 ## Minimum number of packets in pfifo
PACKETSIZE=450 # Bytes per game packet avg
MAXDEL=25 # Ms we try to keep max delay below for game packets after burst

##############################
# netem Qdisc Settings (Optional)
##############################

# netem (Network Emulator) is a tool for testing network conditions by simulating
# latency, packet loss, jitter, and other network phenomena. It's primarily used
# for testing and is not recommended for active gaming sessions as it intentionally
# introduces delay and variability to mimic different network conditions.

netemdelayms="1"
netemjitterms="7"
netemdist="normal"

pktlossp="none" # set to "none" for no packet loss, or use a fraction
		# like 0.015 for 1.5% packet loss in the realtime UDP
		# streams

#############################

if [ $gameqdisc != "fq_codel" -a $gameqdisc != "red" -a $gameqdisc != "pfifo" -a $gameqdisc != "netem" ]; then
    echo "Other qdiscs are not tested and do not work on OpenWrt yet anyway, reverting to red"
    gameqdisc="red"
fi
#############################

##############################
# Port/IP settings for traffic categorization
##############################

## Help the system prioritize your gaming by telling it what is bulk
## traffic ... define a list of udp and tcp ports used for bulk
## traffic such as torrents. By default we include the transmission
## torrent client default port 51413 and the default TCP ports for
## bittorrent. Use comma separated values or ranges A:B as shown. Set
## your torrent client to use a known port and include it here

UDPBULKPORT="51413"
TCPBULKPORT="51413,6881-6889"
VIDCONFPORTS="10000,3478-3479,8801-8802,19302-19309,5938,53"
REALTIME4="192.168.1.208" # example, just add all your game console here
REALTIME6="fd90::129a" ## example only replace with game console
LOWPRIOLAN4="192.168.109.2" # example, add your low priority lan machines here
LOWPRIOLAN6="fd90::129a" ## example, add your low priority lan ipv6 PUBLIC addr here

# Set the ACK rate to 5% of the upload bandwidth. This allocation helps ensure that ACK packets,
# which are essential for maintaining smooth TCP connections, do not overwhelm the network.
# By limiting ACK traffic to a small percentage of the total bandwidth, we prevent these packets
# from interfering with higher priority gaming traffic, thus reducing latency and improving
# overall network performance during gaming sessions.
ACKRATE="$(($UPRATE * 5 / 100))" # auto moode - or set manual
#ACKRATE="300"  ## 300-600 ist a good starting point - or leave blank to disable

FIRST500MS=$((DOWNRATE * 500 / 8)) # downrate * 500/8
FIRST10S=$((DOWNRATE * 10000 / 8)) # downrate * 10000/8

# Control whether to limit UDP traffic going faster than 450 pps
UDP_RATE_LIMIT_ENABLED="yes"  # Set to "yes" to enable or "no" to disable

##############################
#  Traffic washing settings
##############################

WASHDSCPUP="yes"
WASHDSCPDOWN="yes"

######################################## CUSTOMIZATIONS GO ABOVE THIS LINE ###############################################
##########################################################################################################################

##############################
# Function to preserve configuration files
##############################
preserve_config_files() {
    if [ "$PRESERVE_CONFIG_FILES" = "yes" ]; then
        {
            echo "/etc/SimpleHFSCgamerscript.sh"
            echo "/etc/init.d/SimpleHFSCgamerscript"
            echo "/etc/hotplug.d/iface/13-SimpleHFSCGamerScriptHotplug" 
        } | while read LINE; do
            grep -qxF "$LINE" /etc/sysupgrade.conf || echo "$LINE" >> /etc/sysupgrade.conf
        done
        echo "Config files have been added to sysupgrade.conf for preservation."
    else
        echo "Preservation of config files is disabled."
             
        # Remove the config files from sysupgrade.conf if they exist
        sed -i '\|/etc/SimpleHFSCgamerscript.sh|d' /etc/sysupgrade.conf
        sed -i '\|/etc/init.d/SimpleHFSCgamerscript|d' /etc/sysupgrade.conf
        sed -i '\|/etc/hotplug.d/iface/13-SimpleHFSCGamerScriptHotplug|d' /etc/sysupgrade.conf
    fi
}

preserve_config_files

##############################
# Variable checks and dynamic rule generation
##############################

# Function to calculate different ACK rates based on the existing ACKRATE variable
calculate_ack_rates() {
    if [ -n "$ACKRATE" ] && [ "$ACKRATE" -gt 0 ]; then
        SLOWACKRATE=$ACKRATE
        MEDACKRATE=$ACKRATE
        FASTACKRATE=$(($ACKRATE * 10))
        XFSTACKRATE=$(($ACKRATE * 100))
    fi
}

# Call the function to perform the ACK rates calculations
calculate_ack_rates

# Check if the configuration exists and is up to date
check_and_update_config() {
    local config_path="/etc/config/hfscscript"
    if [ ! -f "$config_path" ]; then
        echo "Configuration file not found, downloading the latest version..."
        wget -O $config_path "https://raw.githubusercontent.com/hudra0/routerperf/master/hfscscript" || {
            echo "Error downloading configuration."
            return 1  # Abort on failure
        }
    fi
}

# Call the function at the start of the script
check_and_update_config

create_nft_rule() {
    local config="$1"
    local src_ip src_port dest_ip dest_port proto class counter

    config_get src_ip "$config" src_ip
    config_get src_port "$config" src_port
    config_get dest_ip "$config" dest_ip
    config_get dest_port "$config" dest_port
    config_get proto "$config" proto
    config_get class "$config" class
    config_get_bool counter "$config" counter 0

    # Convert class and proto to lowercase
    class=$(echo "$class" | tr 'A-Z' 'a-z')
    proto=$(echo "$proto" | tr 'A-Z' 'a-z')

    # Ensure class is not empty
    if [ -z "$class" ]; then
        echo "Error: Class for rule '$config' is empty."
        return 1
    fi

    # Initialize rule string
    local rule_cmd=""
    local proto_prefix="$proto"

    # Append source IP and port if provided
    [ -n "$src_ip" ] && rule_cmd="$rule_cmd ip saddr $src_ip "
    [ -n "$src_port" ] && rule_cmd="$rule_cmd $proto_prefix sport $src_port "

    # Append destination IP and port if provided
    [ -n "$dest_ip" ] && rule_cmd="$rule_cmd ip daddr $dest_ip "
    [ -n "$dest_port" ] && rule_cmd="$rule_cmd $proto_prefix dport $dest_port "

    # Append class and counter if provided
    rule_cmd="$rule_cmd ip dscp set $class "
    [ "$counter" -eq 1 ] && rule_cmd="$rule_cmd counter "

    # Finalize the rule by removing any extra spaces and adding a semicolon
    rule_cmd=$(echo "$rule_cmd" | sed 's/[ ]*$//')

    # Ensure the rule is not just a semicolon
    if [ -n "$rule_cmd" ] && [ "$rule_cmd" != ";" ]; then
        echo "$rule_cmd;"
    fi
}

generate_dynamic_nft_rules() {
    . /lib/functions.sh
    config_load 'hfscscript'

    config_foreach create_nft_rule rule
}

# Generate dynamic rules
DYNAMIC_RULES=$(generate_dynamic_nft_rules)


# Check if ACKRATE is greater than 0
if [ "$ACKRATE" -gt 0 ]; then
    ack_rules="\
ip protocol tcp tcp flags & ack == ack meta length < 100 add @xfst4ack {ip daddr . ip saddr . tcp dport . tcp sport limit rate over ${XFSTACKRATE}/second} counter jump drop995
        ip protocol tcp tcp flags & ack == ack meta length < 100 add @fast4ack {ip daddr . ip saddr . tcp dport . tcp sport limit rate over ${FASTACKRATE}/second} counter jump drop95
        ip protocol tcp tcp flags & ack == ack meta length < 100 add @med4ack {ip daddr . ip saddr . tcp dport . tcp sport limit rate over ${MEDACKRATE}/second} counter jump drop50
        ip protocol tcp tcp flags & ack == ack meta length < 100 add @slow4ack {ip daddr . ip saddr . tcp dport . tcp sport limit rate over ${SLOWACKRATE}/second} counter jump drop50"
else
    ack_rules="# ACK rate regulation disabled as ACKRATE=0 or not set."
fi

# Check if UDPBULKPORT is set
if [ -n "$UDPBULKPORT" ]; then
    udpbulkport_rules="\
ip protocol udp udp sport \$udpbulkport ip dscp set cs1 counter
        ip6 nexthdr udp udp sport \$udpbulkport ip6 dscp set cs1 counter
        ip protocol udp udp dport \$udpbulkport ip dscp set cs1 counter
        ip6 nexthdr udp udp dport \$udpbulkport ip6 dscp set cs1 counter"
else
    udpbulkport_rules="# UDP Bulk Port rules disabled, no ports defined."
fi

# Check if TCPBULKPORT is set
if [ -n "$TCPBULKPORT" ]; then
    tcpbulkport_rules="\
ip protocol tcp tcp sport \$tcpbulkport ip dscp set cs1 counter
        ip6 nexthdr tcp tcp sport \$tcpbulkport ip6 dscp set cs1 counter
        ip protocol tcp tcp dport \$tcpbulkport ip dscp set cs1 counter
        ip6 nexthdr tcp tcp dport \$tcpbulkport ip6 dscp set cs1 counter"
else
    tcpbulkport_rules="# UDP Bulk Port rules disabled, no ports defined."
fi

# Check if VIDCONFPORTS is set
if [ -n "$VIDCONFPORTS" ]; then
    vidconfports_rules="\
ip protocol udp udp dport \$vidconfports ip dscp set cs4 counter
        ip6 nexthdr udp udp dport \$vidconfports ip6 dscp set cs4 counter"
else
    vidconfports_rules="# VIDCONFPORTS Port rules disabled, no ports defined."
fi

# Check if REALTIME4 and REALTIME6 are set
if [ -n "$REALTIME4" ]; then
    realtime4_rules="\
ip protocol udp ip daddr \$realtime4 ip dscp set cs5 counter
        ip protocol udp ip saddr \$realtime4 ip dscp set cs5 counter"
else
    realtime4_rules="# REALTIME4 rules disabled, address not defined."
fi

if [ -n "$REALTIME6" ]; then
    realtime6_rules="\
ip6 nexthdr udp ip6 daddr \$realtime6 ip6 dscp set cs5 counter
        ip6 nexthdr udp ip6 saddr \$realtime6 ip6 dscp set cs5 counter"
else
    realtime6_rules="# REALTIME6 rules disabled, address not defined."
fi

# Check if LOWPRIOLAN4 and LOWPRIOLAN6 are set
if [ -n "$LOWPRIOLAN4" ]; then
    lowpriolan4_rules="\
ip protocol udp ip daddr \$lowpriolan4 ip dscp set cs2 counter
        ip protocol udp ip saddr \$lowpriolan4 ip dscp set cs2 counter"
else
    lowpriolan4_rules="# LOWPRIOLAN4 rules disabled, address not defined."
fi

if [ -n "$LOWPRIOLAN6" ]; then
    lowpriolan6_rules="\
ip6 nexthdr udp ip6 daddr \$lowpriolan6 ip6 dscp set cs2 counter
        ip6 nexthdr udp ip6 saddr \$lowpriolan6 ip6 dscp set cs2 counter"
else
    lowpriolan6_rules="# LOWPRIOLAN6 rules disabled, address not defined."
fi

# Check if UDP rate limiting should be applied
if [ "$UDP_RATE_LIMIT_ENABLED" = "yes" ]; then
    udp_rate_limit_rules="\
ip protocol udp ip dscp > cs2 add @udp_meter4 {ip saddr . ip daddr . udp sport . udp dport limit rate over 450/second} counter ip dscp set cs2 counter
        ip6 nexthdr udp ip6 dscp > cs2 add @udp_meter6 {ip6 saddr . ip6 daddr . udp sport . udp dport limit rate over 450/second} counter ip6 dscp set cs2 counter"
else
    udp_rate_limit_rules="# UDP rate limiting is disabled."
fi

##############################
#       dscptag.nft
##############################

## Check if the folder does not exist
if [ ! -d "/usr/share/nftables.d/ruleset-post" ]; then
    mkdir -p "/usr/share/nftables.d/ruleset-post"
fi

cat << DSCPEOF > /usr/share/nftables.d/ruleset-post/dscptag.nft

define udpbulkport = {$UDPBULKPORT}
define tcpbulkport = {$TCPBULKPORT}
define vidconfports = {$VIDCONFPORTS}
define realtime4 = {$REALTIME4}
define realtime6 = {$REALTIME6}
define lowpriolan4 = {$LOWPRIOLAN4}
define lowpriolan6 = {$LOWPRIOLAN6}

define downrate = $DOWNRATE
define uprate = $UPRATE

define first500ms = $FIRST500MS
define first10s = $FIRST10S

define wan = "$WAN"


table inet dscptag # forward declaration so the next command always works

delete table inet dscptag # clear all the rules

table inet dscptag {

    map priomap { type dscp : classid ;
        elements =  {ef : 1:11, cs5 : 1:11, cs6 : 1:11, cs7 : 1:11,
                    cs4 : 1:12, af41 : 1:12, af42 : 1:12,
                    cs2 : 1:14 , cs1 : 1:15, cs0 : 1:13}
    }


    set xfst4ack { typeof ip daddr . ip saddr . tcp dport . tcp sport
        flags dynamic;
        timeout 5m
    }
    set fast4ack { typeof ip daddr . ip saddr . tcp dport . tcp sport
        flags dynamic;
        timeout 5m
    }
    set med4ack { typeof ip daddr . ip saddr . tcp dport . tcp sport
        flags dynamic;
        timeout 5m
    }
    set slow4ack { typeof ip daddr . ip saddr . tcp dport . tcp sport
        flags dynamic;
        timeout 5m
    }
    set udp_meter4 {typeof ip saddr . ip daddr . udp sport . udp dport
        flags dynamic;
        timeout 5m
    }
    set udp_meter6 {typeof ip6 saddr . ip6 daddr . udp sport . udp dport
        flags dynamic;
        timeout 5m
    }
    set slowtcp4 {typeof ip saddr . ip daddr . tcp sport . tcp dport
        flags dynamic;
        timeout 5m
    }
    set slowtcp6 {typeof ip6 saddr . ip6 daddr . tcp sport . tcp dport
        flags dynamic;
        timeout 5m
    }

    chain drop995 {
        numgen random mod 1000 < 995 drop
    }
    chain drop95 {
        numgen random mod 100 < 95 drop
    }
    chain drop50 {
        numgen random mod 100 < 50 drop
    }


    chain dscptag {
        type filter hook forward priority 0; policy accept;

        
        $(if [ "$WASHDSCPDOWN" = "yes" ]; then
            echo "# wash all the DSCP to begin with ... "
            echo "        ip dscp set cs0 counter"
            echo "        ip6 dscp set cs0 counter"
          fi
        )

        $udpbulkport_rules

        $tcpbulkport_rules

        $ack_rules

        $vidconfports_rules

        $realtime4_rules

        $realtime6_rules

        $lowpriolan4_rules

        $lowpriolan6_rules

        $udp_rate_limit_rules

        #downgrade udp going faster than 450 pps, probably not realtime traffic
        ip protocol udp ip dscp > cs2 add @udp_meter4 {ip saddr . ip daddr . udp sport . udp dport limit rate over 450/second} counter ip dscp set cs2 counter
        ip6 nexthdr udp ip6 dscp > cs2 add @udp_meter6 {ip6 saddr . ip6 daddr . udp sport . udp dport limit rate over 450/second} counter ip6 dscp set cs2 counter

        # down prioritize the first 500ms of tcp packets
        ip protocol tcp ct bytes < \$first500ms ip dscp < cs4 ip dscp set cs2 counter

        # downgrade tcp that has transferred more than 10 seconds worth of packets
        ip protocol tcp ct bytes > \$first10s ip dscp < cs4 ip dscp set cs1 counter

        ## tcp with less than 150 pps gets upgraded to cs4
        ip protocol tcp add @slowtcp4 {ip saddr . ip daddr . tcp sport . tcp dport limit rate 150/second burst 150 packets } ip dscp set cs4 counter
        ip6 nexthdr tcp add @slowtcp6 {ip6 saddr . ip6 daddr . tcp sport . tcp dport limit rate 150/second burst 150 packets} ip6 dscp set cs4 counter

${DYNAMIC_RULES}

        ## classify for the HFSC queues:
        meta priority set ip dscp map @priomap counter
        meta priority set ip6 dscp map @priomap counter

        # Store DSCP in conntrack for restoration on ingress
        ct mark set ip dscp or 128 counter
        ct mark set ip6 dscp or 128 counter

        $(if [ "$WASHDSCPUP" = "yes" ]; then
            echo "meta oifname \$wan ip dscp set cs0"
            echo "        meta oifname \$wan ip6 dscp set cs0"
          fi
        )

    }
    
}
DSCPEOF


if [ "$DOWNSHAPING_METHOD" = "veth" ]; then
    ip link show lanveth || ip link add lanveth type veth peer name lanbrport
    LAN=lanveth
    ip link set lanveth up
    ip link set lanbrport up
    ip link set lanbrport master $LANBR
    ip route flush table 100
    ip route add default dev $LAN table 100
    ip -6 route add default dev $LAN table 100
    ip rule add iif $WAN priority 100 table 100
    ip -6 rule add iif $WAN priority 100 table 100
elif [ "$DOWNSHAPING_METHOD" = "ctinfo" ]; then
    # Set up ingress handle for WAN interface
    tc qdisc add dev $WAN handle ffff: ingress
    # Create IFB interface
    ip link add name ifb-$WAN type ifb
    ip link set ifb-$WAN up
    # Redirect ingress traffic from WAN to IFB and restore DSCP from conntrack
    tc filter add dev $WAN parent ffff: protocol all matchall action ctinfo dscp 63 128 mirred egress redirect dev ifb-$WAN
    LAN=ifb-$WAN
elif [ "$DOWNSHAPING_METHOD" = "lan" ]; then
    # No additional setup needed for direct shaping on LAN interface
    :
else
    echo "Invalid downstream shaping method: $DOWNSHAPING_METHOD"
    exit 1
fi

cat <<EOF

This script prioritizes the UDP packets from / to a set of gaming
machines into a real-time HFSC queue with guaranteed total bandwidth 

Based on your settings:

Game upload guarantee = $GAMEUP kbps
Game download guarantee = $GAMEDOWN kbps

Download direction only works if you install this on a *wired* router
and there is a separate AP wired into your network, because otherwise
there are multiple parallel queues for traffic to leave your router
heading to the LAN.

Based on your link total bandwidth, the **minimum** amount of jitter
you should expect in your network is about:

UP = $(((1500*8)*3/UPRATE)) ms

DOWN = $(((1500*8)*3/DOWNRATE)) ms

In order to get lower minimum jitter you must upgrade the speed of
your link, no queuing system can help.

Please note for your display rate that:

at 30Hz, one on screen frame lasts:   33.3 ms
at 60Hz, one on screen frame lasts:   16.6 ms
at 144Hz, one on screen frame lasts:   6.9 ms

This means the typical gamer is sensitive to as little as on the order
of 5ms of jitter. To get 5ms minimum jitter you should have bandwidth
in each direction of at least:

$((1500*8*3/5)) kbps

The queue system can ONLY control bandwidth and jitter in the link
between your router and the VERY FIRST device in the ISP
network. Typically you will have 5 to 10 devices between your router
and your gaming server, any of those can have variable delay and ruin
your gaming, and there is NOTHING that your router can do about it.

EOF


setqdisc () {
DEV=$1
RATE=$2
MTU=1500
highrate=$((RATE*90/100))
lowrate=$((RATE*10/100))
gamerate=$3
useqdisc=$4
DIR=$5


tc qdisc del dev "$DEV" root > /dev/null 2>&1

case $LINKTYPE in
    "atm")
	tc qdisc replace dev "$DEV" handle 1: root stab mtu 2047 tsize 512 mpu 68 overhead ${OH} linklayer atm hfsc default 13
	;;
    "DOCSIS")
	tc qdisc replace dev $DEV stab overhead 25 linklayer ethernet handle 1: root hfsc default 13
	;;
    *)
	tc qdisc replace dev $DEV stab overhead 40 linklayer ethernet handle 1: root hfsc default 13
	;;
esac
     

DUR=$((5*1500*8/RATE))
if [ $DUR -lt 25 ]; then
    DUR=25
fi

# if we're on the LAN side, create a queue just for traffic from the
# router, like LUCI and DNS lookups
if [ $DIR = "lan" ]; then
    tc class add dev "$DEV" parent 1: classid 1:2 hfsc ls m1 50000kbit d "${DUR}ms" m2 10000kbit
fi


#limit the link overall:
tc class add dev "$DEV" parent 1: classid 1:1 hfsc ls m2 "${RATE}kbit" ul m2 "${RATE}kbit"




gameburst=$((gamerate*10))
if [ $gameburst -gt $((RATE*97/100)) ] ; then
    gameburst=$((RATE*97/100));
fi


# high prio realtime class
tc class add dev "$DEV" parent 1:1 classid 1:11 hfsc rt m1 "${gameburst}kbit" d "${DUR}ms" m2 "${gamerate}kbit"

# fast non-realtime
tc class add dev "$DEV" parent 1:1 classid 1:12 hfsc ls m1 "$((RATE*70/100))kbit" d "${DUR}ms" m2 "$((RATE*30/100))kbit"

# normal
tc class add dev "$DEV" parent 1:1 classid 1:13 hfsc ls m1 "$((RATE*20/100))kbit" d "${DUR}ms" m2 "$((RATE*45/100))kbit"

# low prio
tc class add dev "$DEV" parent 1:1 classid 1:14 hfsc ls m1 "$((RATE*7/100))kbit" d "${DUR}ms" m2 "$((RATE*15/100))kbit"

# bulk
tc class add dev "$DEV" parent 1:1 classid 1:15 hfsc ls m1 "$((RATE*3/100))kbit" d "${DUR}ms" m2 "$((RATE*10/100))kbit"



## set this to "drr" or "qfq" to differentiate between different game
## packets, or use "pfifo" to treat all game packets equally

## games often use a 1/64 s = 15.6ms tick rate +- if we're getting so
## many packets that it takes that long to drain at full RATE, we're
## in trouble, because then everything lags by a full tick... so we
## set our RED minimum to start dropping at 9ms of packets at full
## line rate, and then drop 100% by 3x that much, it's better to drop
## packets for a little while than play a whole game lagged by a full
## tick

REDMIN=$((RATE*MAXDEL/3/8)) 

REDMAX=$((RATE * MAXDEL/8)) 

# for fq_codel
INTVL=$((100+2*1500*8/RATE))
TARG=$((540*8/RATE+4))



case $useqdisc in
    "drr")
	tc qdisc add dev "$DEV" parent 1:11 handle 2:0 drr
	tc class add dev "$DEV" parent 2:0 classid 2:1 drr quantum 8000
	tc qdisc add dev "$DEV" parent 2:1 handle 10: red limit 150000 min $REDMIN max $REDMAX avpkt 500 bandwidth ${RATE}kbit probability 1.0
	tc class add dev "$DEV" parent 2:0 classid 2:2 drr quantum 4000
	tc qdisc add dev "$DEV" parent 2:2 handle 20: red limit 150000 min $REDMIN max $REDMAX avpkt 500 bandwidth ${RATE}kbit probability 1.0
	tc class add dev "$DEV" parent 2:0 classid 2:3 drr quantum 1000
	tc qdisc add dev "$DEV" parent 2:3 handle 30: red limit 150000  min $REDMIN max $REDMAX avpkt 500 bandwidth ${RATE}kbit probability 1.0
	## with this send high priority game packets to 10:, medium to 20:, normal to 30:
	## games will not starve but be given relative importance based on the quantum parameter
    ;;

    "qfq")
	tc qdisc add dev "$DEV" parent 1:11 handle 2:0 qfq
	tc class add dev "$DEV" parent 2:0 classid 2:1 qfq weight 8000
	tc qdisc add dev "$DEV" parent 2:1 handle 10: red limit 150000  min $REDMIN max $REDMAX avpkt 500 bandwidth ${RATE}kbit probability 1.0
	tc class add dev "$DEV" parent 2:0 classid 2:2 qfq weight 4000
	tc qdisc add dev "$DEV" parent 2:2 handle 20: red limit 150000 min $REDMIN max $REDMAX avpkt 500 bandwidth ${RATE}kbit probability 1.0
	tc class add dev "$DEV" parent 2:0 classid 2:3 qfq weight 1000
	tc qdisc add dev "$DEV" parent 2:3 handle 30: red limit 150000  min $REDMIN max $REDMAX avpkt 500 bandwidth ${RATE}kbit probability 1.0
	## with this send high priority game packets to 10:, medium to 20:, normal to 30:
	## games will not starve but be given relative importance based on the weight parameter

    ;;

    "pfifo")
	tc qdisc add dev "$DEV" parent 1:11 handle 10: pfifo limit $((PFIFOMIN+MAXDEL*RATE/8/PACKETSIZE))
	;;
    "red")
	tc qdisc add dev "$DEV" parent 1:11 handle 10: red limit 150000 min $REDMIN max $REDMAX avpkt 500 bandwidth ${RATE}kbit  probability 1.0
	## send game packets to 10:, they're all treated the same
	;;
    "fq_codel")
	tc qdisc add dev "$DEV" parent "1:11" fq_codel memory_limit $((RATE*200/8)) interval "${INTVL}ms" target "${TARG}ms" quantum $((MTU * 2))
	;;
    "netem")
	tc qdisc add dev "$DEV" parent 1:11 handle 10: netem limit $((4+9*RATE/8/500)) delay "${netemdelayms}ms" "${netemjitterms}ms" distribution "$netemdist"
	;;


esac

if [ "$DOWNSHAPING_METHOD" = "ctinfo" ] && [ "$DIR" = "lan" ]; then
    # Apply the filters on the IFB interface's egress
    tc filter add dev $DEV parent 1: protocol ip prio 1 u32 match ip dsfield 0xb8 0xfc classid 1:11 # ef (46)
    tc filter add dev $DEV parent 1: protocol ip prio 1 u32 match ip dsfield 0xa0 0xfc classid 1:11 # cs5 (40)
    tc filter add dev $DEV parent 1: protocol ip prio 1 u32 match ip dsfield 0xc0 0xfc classid 1:11 # cs6 (48)
    tc filter add dev $DEV parent 1: protocol ip prio 1 u32 match ip dsfield 0xe0 0xfc classid 1:11 # cs7 (56)
    tc filter add dev $DEV parent 1: protocol ip prio 1 u32 match ip dsfield 0x80 0xfc classid 1:12 # cs4 (32)
    tc filter add dev $DEV parent 1: protocol ip prio 1 u32 match ip dsfield 0x88 0xfc classid 1:12 # af41 (34)
    tc filter add dev $DEV parent 1: protocol ip prio 1 u32 match ip dsfield 0x90 0xfc classid 1:12 # af42 (36)
    tc filter add dev $DEV parent 1: protocol ip prio 1 u32 match ip dsfield 0x40 0xfc classid 1:14 # cs2 (16)
    tc filter add dev $DEV parent 1: protocol ip prio 1 u32 match ip dsfield 0x20 0xfc classid 1:15 # cs1 (8)
    tc filter add dev $DEV parent 1: protocol ip prio 1 u32 match ip dsfield 0x00 0xfc classid 1:13 # none (0)
fi

echo "adding fq_codel qdisc for non-game traffic"
for i in 12 13 14 15; do 
    tc qdisc add dev "$DEV" parent "1:$i" fq_codel memory_limit $((RATE*200/8)) interval "${INTVL}ms" target "${TARG}ms" quantum $((MTU * 2))
done


}


setqdisc $WAN $UPRATE $GAMEUP $gameqdisc wan

setqdisc $LAN $DOWNRATE $GAMEDOWN $gameqdisc lan

echo "DONE!"


if [ "$gameqdisc" = "red" ]; then
   echo "Can not output tc -s qdisc because it crashes on OpenWrt when using RED qdisc, but things are working!"
else
   tc -s qdisc
fi

