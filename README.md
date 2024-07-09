
  
# Router custom QoS script: SimpleHFSCgamerscript.sh

SimpleHFSCgamerscript is a shell script designed to set up highly responsive QoS (Quality of Service) for routers running OpenWrt, specifically tailored for gaming applications. 
## Features

- Automatically installs necessary packages and downloads required files - no additional install script needed
- Supports modern nftables-based firewalls (fw4 or custom)
- Easy to start, stop, and monitor the script's operation
- Cleans up qdiscs, veth interfaces, and nftables rules when stopped
- Customizable settings for network interfaces, speeds, and gaming traffic allocation
- Dynamically generates nftables rules based on user-defined settings
- Supports custom DSCP marking rules via UCI configuration
- Automatically adjusts ACK rate to prevent bandwidth saturation
- Flexible configuration options to adapt to various network setups

## How to Use SimpleHFSCgamerscript - A quick setup guide

  Before installing SimpleHFSCgamerscript, make sure to:

- **Disable any existing QoS services** such as SQM or Qosify on your router to avoid conflicts with the new script.
- Upon first start, it's best to **reboot your router** to clear out all old settings for a clean start.
- **Install SimpleHFSCgamerscript** following the provided instructions, then adjust settings to suit your network needs:

1. Log into your OpenWrt router and download the scripts to your router with this command:

```
wget -O /etc/init.d/SimpleHFSCgamerscript https://raw.githubusercontent.com/hudra0/routerperf/master/SimpleHFSCgamerscript && chmod +x /etc/init.d/SimpleHFSCgamerscript && wget -O /etc/SimpleHFSCgamerscript.sh https://raw.githubusercontent.com/hudra0/routerperf/master/SimpleHFSCgamerscript.sh && chmod +x /etc/SimpleHFSCgamerscript.sh
```   
  This command does the following:
- Downloads the init script to `/etc/init.d/SimpleHFSCgamerscript` and makes it executable.
- Grabs the main script and saves it to `/etc/SimpleHFSCgamerscript.sh`, then makes that executable too.
2. Edit the `SimpleHFSCgamerscript.sh` file to adapt the settings to your network environment. The most important settings are:
    - `WAN` and `LAN`: Specify the names of your WAN and LAN interfaces here (e.g., `eth0` for LAN and `eth1` for WAN).
    - `UPRATE` and `DOWNRATE`: Enter about 80 - 90 % of your actual upload and download speed here to ensure optimal performance. These values are specified in kilobits per second (kbps).
    - `GAMEUP` and `GAMEDOWN`: Here you can set the bandwidth to be reserved for gaming. By default, these values are calculated based on `UPRATE` and `DOWNRATE`, but you can adjust them if needed.
3. Choose the appropriate method for shaping downstream traffic:
    - If you are using a router with combined wired and wireless access, set `DOWNSHAPING_METHOD="ctinfo"` (recommended).
    - For a veth-based configuration, set `DOWNSHAPING_METHOD="veth"` and make sure `LANBR` is set to the name of your LAN bridge (default is `br-lan`).
4. Prioritize traffic from your gaming devices:
    - Add the IP addresses of your gaming devices to the `REALTIME4` (for IPv4) and `REALTIME6` (for IPv6) variables. UDP traffic from these devices will end up in the  real-time queue.
    - Alternatively, you can also prioritize specific ports for your games by using [custom DSCP marking rules](#custom-dscp-marking-rules). This is especially useful if your gaming device is a PC where other UDP traffic (like QUIC for YouTube videos) could otherwise end up in the real-time queue.
5. Adjust the prioritization for other devices and applications (optional):
    
    - Add the IP addresses of low-priority devices to the `LOWPRIOLAN4` (for IPv4) and `LOWPRIOLAN6` (for IPv6) variables.
    - Define the ports for bulk traffic (e.g., torrent clients) in the `UDPBULKPORT` and `TCPBULKPORT` variables. Use single port numbers or ranges (e.g., `51413` or `6881-6889`).
    - Specify the ports for video conferencing in the `VIDCONFPORTS` variable.
    
    Here's an example configuration for the mentioned variables:

    
```
	UDPBULKPORT="51413"
	TCPBULKPORT="51413,6881-6889"
	VIDCONFPORTS="10000,3478-3479,8801-8802,19302-19309,5938,53"
	REALTIME4="192.168.1.208" # Add the IP addresses of your gaming consoles here
	REALTIME6="fd90::129a" # Replace this with the IPv6 address of your gaming console
	LOWPRIOLAN4="192.168.109.2" # Add the IP addresses of low-priority devices here
	LOWPRIOLAN6="fd90::129a" # Add the IPv6 addresses of low-priority devices here
```

6. To get everything rolling, enable and start the service with:
    
    
    
```
/etc/init.d/SimpleHFSCgamerscript enable
/etc/init.d/SimpleHFSCgamerscript start
## or 
service SimpleHFSCgamerscript enable 
service SimpleHFSCgamerscript start
```
    
You can also do this via LuCI (System/Startup).

-  edit /etc/config/hfscscript to add any additional rules you want to use for custom DSCP tagging - examples are in the config

7. To make sure everything's running smoothly, you can check the service status:
    
    
    `/etc/init.d/SimpleHFSCgamerscript status`

For more detailed explanations of the individual settings, refer to the [Detailed Configuration](#detailed-configuration) section.

#### Verification and Monitoring

After starting the script, use the following commands to ensure it is running correctly and the QoS settings are applied as expected.

**Checking the Classes**

Use `tc -s qdisc` to check if all classes are created on the egress and ingress interfaces:

```
tc -s qdisc
```

Make sure the output shows the following classes:

- **Egress Interface (WAN - for example eth1, pppoe-wan...)**:
    
    - Classes 1:11 to 1:15 
- **Ingress Interface (e.g., ifb-eth1, ifb-pppoe-wan, lanveth (for veth method), eth0 (lan method)...)**:
    
    - Classes 1:11 to 1:15

**Sample Output**

A sample output might look like this:
```
qdisc hfsc 1: dev ifb-eth1 root refcnt 2 default 13 
 Sent 3522537205 bytes 3908374 pkt (dropped 5063, overlimits 2261121 requeues 0) 
 backlog 0b 0p requeues 0
qdisc fq_codel 80ba: dev ifb-eth1 parent 1:12 limit 10240p flows 1024 quantum 3000 target 4ms interval 100ms memory_limit 2250000b ecn drop_batch 64 
 Sent 1505178098 bytes 1767854 pkt (dropped 260, overlimits 0 requeues 0) 
 backlog 0b 0p requeues 0
  maxpacket 24722 drop_overlimit 0 new_flow_count 96335 ecn_mark 0
  new_flows_len 0 old_flows_len 1
qdisc fq_codel 80bc: dev ifb-eth1 parent 1:14 limit 10240p flows 1024 quantum 3000 target 4ms interval 100ms memory_limit 2250000b ecn drop_batch 64 
 Sent 0 bytes 0 pkt (dropped 0, overlimits 0 requeues 0) 
 backlog 0b 0p requeues 0
  maxpacket 0 drop_overlimit 0 new_flow_count 0 ecn_mark 0
  new_flows_len 0 old_flows_len 0
qdisc bfifo 10: dev ifb-eth1 parent 1:11 limit 52125b
 Sent 6130 bytes 47 pkt (dropped 0, overlimits 0 requeues 0) 
 backlog 0b 0p requeues 0
qdisc fq_codel 80bb: dev ifb-eth1 parent 1:13 limit 10240p flows 1024 quantum 3000 target 4ms interval 100ms memory_limit 2250000b ecn drop_batch 64 
 Sent 1884214806 bytes 2017446 pkt (dropped 4791, overlimits 0 requeues 0) 
 backlog 0b 0p requeues 0
  maxpacket 23274 drop_overlimit 256 new_flow_count 163741 ecn_mark 0 drop_overmemory 256
  new_flows_len 0 old_flows_len 3
qdisc fq_codel 80bd: dev ifb-eth1 parent 1:15 limit 10240p flows 1024 quantum 3000 target 4ms interval 100ms memory_limit 2250000b ecn drop_batch 64 
 Sent 133137641 bytes 123022 pkt (dropped 0, overlimits 0 requeues 0) 
 backlog 0b 0p requeues 0
  maxpacket 9938 drop_overlimit 0 new_flow_count 6868 ecn_mark 0
  new_flows_len 0 old_flows_len 2
```

If you look closely you can see all classes (1:11 to 1:15) for the ingress interface (ifb-eth1)
## Detailed Configuration
### General Settings

- `LINKTYPE`: Set to "atm" for old-school DSL, "DOCSIS" for cable modem, or "other" for anything else.
- `WAN`: Change this to your WAN device name (e.g., eth1).
- `LAN`: Change this to your LAN device.
- `DOWNRATE`: Set this to about 80 - 90% of your download speed in kbps.
- `UPRATE`: Set this to about 80 - 90% of your upload speed in kbps.
- `OH`: Number of bytes of overhead on your line.
- `DOWNSHAPING_METHOD`: Choose between "ctinfo", "veth", or "lan" for downstream shaping.
	- "ctinfo"  Uses connection tracking information to restore DSCP markings on incoming packets
	- "veth" Utilizes a virtual Ethernet pair to control incoming traffic
    -  "lan" Applies traffic shaping directly on the LAN interface, (ideal) for environments with a single interface directed towards the LAN. 
- `LANBR`: LAN bridge interface name, only relevant if using the veth setup.

### Performance Settings

- `GAMEUP` and `GAMEDOWN`: Adjust these values to allocate bandwidth for gaming traffic. You can tune these yourself, but a good starting point is the provided formula.
- `BWMAXRATIO`: This setting limits the download rate to a multiple of the upload rate to prevent ACK packet flooding, which can cause game packet drops. The default value is 20, but you can adjust it based on your network conditions.

### Qdisc Selection

- `gameqdisc`: Select the queueing discipline for gaming traffic (pfifo, bfifo, red, fq_codel, or netem).
    - `pfifo` (Packet FIFO): Simple FIFO queue that handles packets in the order they arrive.
    - `red` (Random Early Detection): Manages congestion by preemptively dropping packets before the queue fills up, based on dynamic thresholds derived from `MAXDEL`.
    - `fq_codel` (Fair Queue Controlled Delay): Targets bufferbloat by adjusting queues to minimize delays, effectively handling multiple data streams.
    - `netem` (Network Emulator): Introduces delays, jitter, or losses for network testing. Use `netemdelayms` to set specific delay values.
- `MAXDEL`: The maximum delay in milliseconds that the script tries to keep game packets below after a burst. Used by pfifo, and red qdiscs.
- `PFIFOMIN`: (PFIFO) The minimum number of packets in the pfifo queue. Adjust this value based on your network's latency and packet loss characteristics.
- `PACKETSIZE`: (PFIFO) The average size of a game packet in bytes.
- `netemdelayms`, `netemjitterms`, `netemdist`, `pktlossp`: These settings are used when the netem qdisc is selected. They allow you to simulate network conditions by introducing delay, jitter, and packet loss for testing purposes.

### Port/IP Settings for Traffic Categorization

- `UDPBULKPORT` and `TCPBULKPORT`: Define a list of UDP and TCP ports used for bulk traffic such as torrents. By default, the Transmission torrent client default port 51413 and the default TCP ports for BitTorrent are included. Use comma-separated values or ranges like A:B.
- `VIDCONFPORTS`: Ports used for video conferencing, such as Zoom, Skype, Google Meet, etc.
- `REALTIME4` and `REALTIME6`: Add the IPv4 and IPv6 addresses of your gaming devices here to prioritize their UDP traffic in real-time.
- `LOWPRIOLAN4` and `LOWPRIOLAN6`: Add the IPv4 and IPv6 addresses of devices in your network that should receive low priority.
- `ACKRATE`: Sets the ACK rate to 5% of the upload bandwidth. This allocation helps ensure that ACK packets, which are essential for maintaining smooth TCP connections, do not overwhelm the network. By limiting ACK traffic to a small percentage of the total bandwidth, we prevent these packets from interfering with higher priority gaming traffic, thus reducing latency and improving performance during gaming sessions. You can manually adjust the value or leave it blank or comment it out to disable the feature.
- `FIRST500MS` and `FIRST10S`: These settings define the bandwidth for the first 500 ms and 10 seconds of a TCP connection, respectively. They are used to adjust the priority of TCP packets based on the amount of data transferred.
- `UDP_RATE_LIMIT_ENABLED`: Controls whether UDP traffic going faster than 450 packets per second (pps) should be limited. Set this to "yes" to enable the feature or "no" to disable it. If your game "likes" when you have low bandwidth, setting `UDP_RATE_LIMIT_ENABLED` to `yes` can cause you to "escape" the bandwidth limits.

### Traffic Washing Settings

- `WASHDSCPUP` and `WASHDSCPDOWN`: Controls whether DSCP markings should be washed for upload and download traffic, respectively. Set these to "no" to preserve custom DSCP markings.

### Custom DSCP Marking Rules

SimpleHFSCgamerscript supports custom DSCP marking rules via the UCI configuration file located at `/etc/config/hfscscript`. You can define simple rules to match traffic based on source/destination ports and IPs, and assign DSCP classes accordingly.

DSCP (Differentiated Services Code Point) is a field in the IP header that is used to classify and prioritize network traffic. By setting specific DSCP values for different types of traffic, you can ensure that high-priority applications, such as gaming, end up in the right priority class/tin.

Each `config rule` section should include the following options:

- `name`: A unique name for the rule.
- `proto`: The protocol (tcp or udp) to match.
- `src_ip`, `src_port`, `dest_ip`, `dest_port`: The source and destination IP addresses and ports to match. Use a single value, a comma-separated list, or a range (e.g., "1000-2000").
- `class`: The DSCP class to assign to matching packets (e.g., cs1, cs2, cs3, cs4, cs5).
- `counter`: Set to "1" to enable packet counters for this rule.

Example:
```
config rule 'cod1'
    option name 'cod1'
    option proto 'udp'
    option src_ip '192.168.1.208'
    option src_port '3074'      
    option dest_port '30000-65535'
    option class 'cs5'
    option counter '1'

config rule 'cod2'
   option name 'cod3'
   option proto 'udp'
   option dest_ip '192.168.1.208'
   option dest_port '3074'      
   option class 'cs5'
   option counter '1'
```


Additionally the script more or less "automatically" supports setting DSCP markings through the LUCI firewall UI. These markings will also be restored upon download  (when ctinfo is enabled). To facilitate this, the script must not "wash" the DSCP in the download direction:

`WASHDSCPDOWN="no"`

And of course, the SimpleHFSCgamerscript should not contain any rules that overwrite the markings subsequently.

A possible example:  

![Pasted image 20240501192403](https://github.com/hudra0/routerperf/assets/117863474/681f266f-df14-4c01-aa3c-5baa0c5de64c)

In uci:

```
config rule
option name 'dscp test'
list proto 'icmp'
list dest_ip '1.1.1.1' 
option target 'DSCP'
option set_dscp 'EF'
option src '*' 
option dest '*'
list src_ip '192.168.1.208'
```
## What this script does:

This script sets up a HFSC queue system on your WAN and LAN ethernet interfaces. It offers 5 classes of traffic. The most important class is 1:11 which is for use by realtime UDP traffic to and from a list of gaming machines which is set by you. Packets with DSCP tags CS5, CS6, CS7 will be sent to the realtime queue. Later when QFQ is available on OpenWrt we may enable sub-prioritizing these, such as making game packets more important than in-game VOIP or things like that.

The remaining classes 1:12, 1:13, 1:14, 1:15 are non-realtime but have different bandwidth and latency behavior when there is contention. You can edit /etc/config/hfscscript to tag DSCP on whatever packets you want to enter each class. Additionally you can add DSCP marks via LUCI Firewall.

- CS4 goes to 1:12 which will have relatively low latency, good for interactive video chats, or casual gaming on a non-dedicated game machine
- CS3 or by default anything else goes to 1:13 which is for normal browsing
- CS2 goes to 1:14 which will tend to pause and allow other traffic to go ahead, this is useful for medium long downloads
- CS1 goes to 1:15 and has very poor bandwidth and long latency when there is contention with other classes. This is good for all-night torrenting etc.

All "normal" classes will use all available bandwidth if they are the only class using bandwidth. The realtime class will only use at most GAMEUP or GAMEDOWN.

In general for high speed connections the realtime bandwidth should be around 10-15% of your bandwidth or less... But when your connections are slow, we need them to be at least what the game actually needs. As a guideline, Call Of Duty used about 160kbps upstream and 320kbps downstream, so a good baseline is about double that each direction. By default we do something smart but you can adjust the script if needed, depending on the game you play.

This script will limit your download to at most 10x your upload, this is to avoid flooding your upload with ACK packets that compete with your gaming during large downloads by other devices. For slow speed connections below 3Mbps, it also does MSS clamping to encourage your TCP streams to use 540 byte packets to reduce the "lumpiness" of your queue thereby reducing jitter and dropped packets.

This should allow you to game on a shared line down to in the range of 700kbps upstream, however of course having higher speed connections will in general be better. A 3000kbps connection and above should have absolutely fluid gaming traffic with proper tuning of the settings. Testers have successfully played with fluid gaming on 16000kbps down / 830kbps up DSL lines.

```
                            [Root Queue (1:)]
                                    |
                    -------------------------
                    |                      |
          [1:2 Router Traffic]    [1:1 Main Link Queue]
                    |                      |
      Special handling for         ├──[1:11 Real-time Gaming Traffic]
      internal router-originated           │     └── Qdiscs:
      traffic                              │           ├─ pfifo
                                           │           ├─ bfifo
                                           │           ├─ fq_codel
                                           │           ├─ red
                                           │           └─ netem
                                           │
                                           ├──[1:12 Fast Non-Realtime Traffic]
                                           │     └── Qdisc: fq_codel
                                           │
                                           ├──[1:13 Normal Traffic]
                                           │     └── Qdisc: fq_codel
                                           │
                                           ├──[1:14 Low Priority Traffic]
                                           │     └── Qdisc: fq_codel
                                           │
                                           └──[1:15 Bulk Traffic]
                                                 └── Qdisc: fq_codel

```
### Troubleshooting

If you encounter issues with the script or want to verify that it's working correctly, follow these steps:

1. Disable DSCP washing up and downloading by setting `WASHDSCPUP="no"` and `WASHDSCPDOWN="no"` in the main script.
2. Update and install tcpdump: `opkg update && opkg install tcpdump`
3. Mark an ICMP ping to a reliable destination (e.g., 1.1.1.1) with a specific DSCP value using the Custom DSCP Marking Rules (UCI configuration).
4. Ping the destination from your LAN client.
5. Use `tcpdump -i eth1 -v -n -Q out icmp` to display outgoing traffic (upload) and verify that the TOS value is not 0x0. Make sure to **set the right interface (WAN Interface).** 
6. Use `tcpdump -i ifb-eth1 -v -n icmp` (replace ifb-eth1 with your actual interface) to display incoming traffic (download) and verify that the TOS value is not 0x0. Make sure to **set the right interface according to your DOWNSHAPING METHOD** 
7. Install watch: `opkg update && opkg install procps-ng-watch`
8. Use `watch -n 2 'tc -s qdisc | grep -A 2 "parent 1:11"'` (replace 1:11 with the desired class) to check if packets are landing in the correct traffic control (tc) queue. The packet count should increase with the ping in both directions.

## Uninstallation

To completely remove SimpleHFSCgamerscript from your OpenWrt router:

1. Stop the script:

`/etc/init.d/SimpleHFSCgamerscript stop`

2. Disable the script from starting on boot:

`/etc/init.d/SimpleHFSCgamerscript disable`

3. Remove the script files:

`rm /etc/init.d/SimpleHFSCgamerscript && rm /etc/SimpleHFSCgamerscript.sh && rm /etc/config/hfscscript`

4. Reboot your router to clear any remaining settings:
`reboot`

## CTInfo and Download Shaping in Linux

One of the key features of SimpleHFSCgamerscript is its ability to shape download traffic using the ctinfo method. This is particularly important because download shaping can be challenging in Linux due to the order in which traffic control (tc) and firewall rules are applied.

### The Challenge of Download Shaping

In Linux, traffic control (tc) rules are applied before firewall rules. This means that when packets arrive at the network interface, they are first processed by the tc rules before being handed off to the firewall. As a result, it becomes difficult to shape download traffic based on firewall rules, as the packets have already been processed by the tc rules at that point.

This is where the ctinfo method comes into play. CTInfo, short for Connection Tracking Information, allows the script to leverage connection tracking data to shape download traffic effectively.

### How CTInfo Works

By leveraging conntrack information, SimpleHFSCgamerscript can effectively shape download traffic according to the desired QoS rules, even though the tc rules are applied before the firewall rules.

Here's a more detailed breakdown of the ctinfo process:

1. Packets are marked in the forward chain using the following rules:
    
        
```
    ct mark set ip dscp or 128 counter
    ct mark set ip6 dscp or 128 counter
```
    
These rules set the 8th bit of the conntrack mark for both IPv4 and IPv6 packets, ensuring that the DSCP value is stored in the conntrack entry.

2. The script sets up an ingress qdisc on the WAN interface and redirects incoming traffic to an Intermediate Functional Block (IFB) device:
    
        
```
    tc qdisc add dev $WAN handle ffff: ingress
    ip link add name ifb-WAN type ifb 
    ip link set ifb-WAN up 
    tc filter add dev WAN parent ffff: protocol all matchall action ctinfo dscp 63 128 mirred egress redirect dev ifb-WAN
```

This step ensures that incoming packets are redirected to the IFB device, where the DSCP value can be restored from the conntrack mark.

3. The script then applies the HFSC rules to the IFB device, allowing for effective download shaping based on the restored DSCP values.

By using the ctinfo method, SimpleHFSCgamerscript overcomes the challenge of download shaping in Linux and ensures that both upload and download traffic are properly shaped according to the defined QoS rules.


## General Thoughts on Gaming and Network Performance

### The Reality of Online Gaming

It's important to acknowledge that online gaming, by its nature, will never be 100% fair. Factors like server location, player distribution, and individual network quality mean that some players will always have an advantage over others. This is why professional esports tournaments are often played on LAN to ensure a level playing field.

As a player, the best you can do is optimize the factors within your control, maintain realistic expectations, and focus on enjoying the game. SimpleHFSCgamerscript, SQM and other scripts are powerful tools in your arsenal, but it's not a panacea for all the challenges of online gaming. By understanding its strengths and limitations, you can make informed decisions about how to set up your home network for the best possible gaming experience.




# Low Latency Daemon for x86 routers

On x86 routers using the intel pstate power saving system, you can
prevent the cpu from going to very low power states by running the
script lowlatencydaemon.lua as follows (can be done in /etc/rc.local)

```
lua lowlatencydaemon.lua
```

It has two tunables, starthr and endhr, which are the hours of the day
that it should run at low latency, by default 6 and 22 so it is in low
latency mode from 6am to 11pm. You can set 0 and 24 if you want low
latency at all times.



# Router performance analysis scripts (other scripts in this github)

This software collects data on a router running OpenWRT (or other
linux) and creates a data file. It also includes scripts to transform
that data file into a file containing a single JSON array, and some
data analysis scripts in R.

The idea is we will eventually crowdsource a bunch of the data files,
and create predictions for reliable SQM shaping bandwidth that each
router supported by OpenWRT can handle. This portion of the project is
no longer active.


