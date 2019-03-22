#!/bin/sh

###########################
# Set global vars
###########################

# iptables path
IPT="/sbin/iptables"

# Working interface
IFACE=eth0


########################
# Starting msg
########################

printf "Loading iptables rules...\n"


#####################################
# Flushing tables
#####################################

# Deleteing chains rules
$IPT -F
$IPT -F -t nat

# Deleting empty non standard chains
$IPT -X

# Counters initizlization (for debugging)
$IPT -Z


###################################################
# Only the OUTPUT chain is ACCEPT
###################################################

$IPT -P INPUT DROP
$IPT -P FORWARD DROP
$IPT -P OUTPUT ACCEPT


##############################
# loopback traffic enabled
##############################

$IPT -A INPUT -i lo -j ACCEPT
$IPT -A OUTPUT -o lo -j ACCEPT


#####################################################
# ICMP ping rules
#####################################################

$IPT -A INPUT -p icmp --icmp-type echo-reply -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPT -A INPUT -p icmp --icmp-type echo-request -m limit --limit 5/s -m state --state NEW -j ACCEPT
$IPT -A INPUT -p icmp --icmp-type destination-unreachable -m state --state NEW -j ACCEPT
$IPT -A INPUT -p icmp --icmp-type time-exceeded -m state --state NEW -j ACCEPT
$IPT -A INPUT -p icmp --icmp-type timestamp-request -m state --state NEW -j ACCEPT
$IPT -A INPUT -p icmp --icmp-type timestamp-reply -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPT -A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT
$IPT -A OUTPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT


###############################################
# spoofing defense
###############################################

$IPT -A INPUT -s 10.0.0.0/8 -j DROP 
$IPT -A INPUT -s 169.254.0.0/16 -j DROP
$IPT -A INPUT -s 172.16.0.0/12 -j DROP
$IPT -A INPUT -s 127.0.0.0/8 -j DROP
$IPT -A INPUT -s 192.168.0.0/24 -j DROP
$IPT -A INPUT -s 192.168.1.0/24 -j DROP
$IPT -A INPUT -s 192.168.10.0/24 -j DROP
$IPT -A INPUT -s 224.0.0.0/4 -j DROP
$IPT -A INPUT -d 224.0.0.0/4 -j DROP
$IPT -A INPUT -s 240.0.0.0/5 -j DROP
$IPT -A INPUT -d 240.0.0.0/5 -j DROP
$IPT -A INPUT -s 0.0.0.0/8 -j DROP
$IPT -A INPUT -d 0.0.0.0/8 -j DROP
$IPT -A INPUT -d 239.255.255.0/24 -j DROP
$IPT -A INPUT -d 255.255.255.255 -j DROP


########################################
# SMURF defense
########################################

$IPT -A INPUT -p icmp -m icmp --icmp-type address-mask-request -j DROP
$IPT -A INPUT -p icmp -m icmp --icmp-type timestamp-request -j DROP
$IPT -A INPUT -p icmp -m icmp --icmp-type 8 -m limit --limit 1/second -j ACCEPT
$IPT -A INPUT -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/second --limit-burst 2 -j ACCEPT


#####################################
# Dropping invalid packets
#####################################

$IPT -A INPUT -m state --state INVALID -j DROP
$IPT -A FORWARD -m state --state INVALID -j DROP
$IPT -A OUTPUT -m state --state INVALID -j DROP


##############################################
# Port scan disabled, logging attempts (default logs path is /var/log/messages)
# IP are blocked for 24 hours
##############################################

$IPT -A INPUT -m recent --name portscan --rcheck --seconds 86400 -j DROP
$IPT -A FORWARD -m recent --name portscan --rcheck --seconds 86400 -j DROP
$IPT -A INPUT -p tcp -m tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "portscan:"
$IPT -A INPUT -p tcp -m tcp --dport 139 -m recent --name portscan --set -j DROP


###############################################
# Block new connection that not starts with SYN
# DOS attacks protection
###############################################

$IPT -N syn-flood
$IPT -A INPUT -i $IFACE -p tcp --syn -j syn-flood
$IPT -A syn-flood -m limit --limit 1/s --limit-burst 4 -j RETURN
$IPT -A syn-flood -j DROP
$IPT -A INPUT -p tcp ! --syn -m state --state NEW -j DROP


#########################################################
# Established connections are allowed
#########################################################

$IPT -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT


#########################################################
# Rules on ports
#########################################################

# 80/443 - HTTP
$IPT -A INPUT -p tcp --dport 80 -m state --state NEW -j ACCEPT
$IPT -A INPUT -p tcp --dport 443 -m state --state NEW -j ACCEPT

# 
$IPT -A INPUT -p tcp --dport <port> -m state --state NEW -j ACCEPT

###############################################################
# Block fragments and Xmas tree as well as SYN,FIN and SYN,RST
###############################################################

$IPT -A INPUT -p ip -f -j DROP
$IPT -A INPUT -p tcp --tcp-flags ALL ACK,RST,SYN,FIN -j DROP
$IPT -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
$IPT -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP


###############################
# Finished msg
###############################

printf "Iptables successfully configured.\n"