#$/bin/sh

# Clear all exsisting rules
iptables -F

# Set default action to drop packets
iptables -P FORWARD DROP
iptables -P OUTPUT DROP
iptables -P INPUT DROP

# Create table for blacklist
iptables -N REDTEAM
iptables -A REDTEAM -m recent --remove
iptables -A REDTEAM -m recent --name redteam --set
iptables -A REDTEAM -j LOG --log-prefix "Redteam Blocked: "

#####SETUP INBOUND RULE ######
# Allow local traffic
iptables -A INPUT -i lo -j ACCEPT

# Prevent SYN packet attacks
iptables -A INPUT -p tcp ! --syn -m state --state NEW -m limit --limit 1/min -j LOG --log-prefix "SYN packet flood: "
iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP

# Prevent fragmented packets
iptables -A INPUT -f -m limit -limit 1/min -j LOG --log-prefix "Fragmented packet: "
iptables -A INPUT -f -j DROP

# Prevent XMAS attacks
iptables -A INPUT -p tcp --tcp-flags ALL ALL -m limit --limit 1/min -j LOG --log-prefix "XMAS packet: "
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP

# Prevent NULL attacks
iptables -A INPUT -p tcp --tcp-flags ALL NONE -m limit --limit 1/min -j LOG --log-prefix "NULL packet: "
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP

# Allow ping with limits
iptables -A INPUT -p icmp -m limit --limit 6/min -j ACCEPT

# Drop packets from blacklisted ip for 10 minutes
iptables -A INPUT -m recent --rcheck --name redteam --seconds 600 -j DROP

# Flag excessive pings as flood attack
iptables -A INPUT -p icmp -m limit --limit 1/minute -j LOG --log-prefix "ICMP Flood: "

# Allow all traffic already established
iptables -A INPUT -m state --state established,related -j ACCEPT

# Remember all ip connections and send excessive requests to blacklist
iptables -A INPUT -m state --state NEW -m recent --set
iptables -A INPUT -m recent --update --seconds 10 --hitcount 20 -j REDTEAM

# Allow email traffic
iptables -A INPUT -p tcp --dport 25 -m state --state new -j ACCEPT
iptables -A INPUT -p tcp --dport 110 -m state --state new -j ACCEPT
iptables -A INPUT -p tcp --dport 143 -m state --state new -j ACCEPT
iptables -A INPUT -p tcp --dport 445 -m state --state new -j ACCEPT
iptables -A INPUT -p tcp --dport 995 -m state --state new -j ACCEPT

# Allow http traffic
iptables -A INPUT -p tcp --dport 80 -m state --state new -j ACCEPT

# Allow https traffic
iptables -A INPUT -p tcp --dport 443 -m state --state new -j ACCEPT

# Allow samba traffic (optional)
#iptables -A INPUT -p tcp --dport 137 -m state --state new -j ACCEPT
#iptables -A INPUT -p tcp --dport 138 -m state --state new -j ACCEPT
#iptables -A INPUT -p tcp --dport 139 -m state --state new -j ACCEPT

#####SETUP OUTBOUND RULES #####
# Allow local traffic
iptables -A OUTPUT -o lo -j ACCEPT

# Allow all traffic already established
iptables -A OUTPUT -m state --state established,related -j ACCEPT

# Allow http traffic
iptables -A OUTPUT -p tcp --dport 80 -m state --state new -j ACCEPT

# Allow ldap traffic
iptables -A OUTPUT -p tcp --dport 389 -m state --state new -j ACCEPT

# Allow https traffic
iptables -A OUTPUT -p tcp --dport 443 -m state --state new -j ACCEPT

# Allow mysql traffic (roundcube)
iptables -A OUTPUT -p tcp --dport 3306 -d 172.20.240.23 -m state --state new -j ACCEPT

# Allow ssh traffic
iptables -A OUTPUT -p tcp --dport 22 -m state --state new -j ACCEPT

# Allow dns traffic
iptables -A OUTPUT -p udp --dport 53 -m state --state new -j ACCEPT

# Allow ntp traffic
iptables -A OUTPUT -p udp --dport 123 -m state --state new -j ACCEPT

# Allow rsyslog traffic to send logs
iptables -A OUTPUT -p udp --dport 514 -m state --state new -j ACCEPT

# Allow ping
iptables -A OUTPUT -p icmp -j ACCEPT

# Log everything else about to be dropped
iptables -A OUTPUT -m limit --limit 2/min -j LOG --log-prefix "Output-Dropped: " --log-level 4
iptables -A INPUT -m limit --limit 2/min -j LOG --log-prefix "Input-Dropped: " --log-level 4
iptables -A FORWARD -m limit --limit 2/min -j LOG --log-prefix "Forward-Dropped: " --log-level 4

# Save the filter rules
/etc/init.d/iptables save
