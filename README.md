# samp-firewall
Dedicated firewall for SA:MP

### Requeriments
```shell
apt-get update
apt-get install -y gcc
apt-get install -y libpcap0.8*
apt-get install -y ipset
```

### Rules
```shell
# Remove rules
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
iptables -t nat -F
iptables -t mangle -F
iptables -t raw -F
iptables -t nat -X
iptables -t mangle -X
iptables -t raw -X
iptables -F
iptables -X

# Initialize lists
ipset -X udp_whitelist -!
ipset -X tcp_whitelist -!

ipset -N udp_whitelist hash:ip hashsize 16777216 maxelem 16777216 -!
ipset -N tcp_whitelist hash:ip hashsize 16777216 maxelem 16777216 -!

# Priority addresses
ipset -A udp_whitelist 147.135.105.73 -!
ipset -A udp_whitelist 127.0.0.1 -!
ipset -A tcp_whitelist 147.135.105.73 -!
ipset -A tcp_whitelist 127.0.0.1 -!
ipset -A tcp_whitelist 170.83.220.2 -!
ipset -A tcp_whitelist 190.79.68.207 -!
ipset -A tcp_whitelist 170.83.223.2 -!

# Cloudflare IPs
ipset -A tcp_whitelist 103.21.244.0/22 -!
ipset -A tcp_whitelist 103.22.200.0/22 -!
ipset -A tcp_whitelist 103.31.4.0/22 -!
ipset -A tcp_whitelist 104.16.0.0/13 -!
ipset -A tcp_whitelist 104.24.0.0/14 -!
ipset -A tcp_whitelist 108.162.192.0/18 -!
ipset -A tcp_whitelist 131.0.72.0/22 -!
ipset -A tcp_whitelist 141.101.64.0/18 -!
ipset -A tcp_whitelist 162.158.0.0/15 -!
ipset -A tcp_whitelist 172.64.0.0/13 -!
ipset -A tcp_whitelist 173.245.48.0/20 -!
ipset -A tcp_whitelist 188.114.96.0/20 -!
ipset -A tcp_whitelist 190.93.240.0/20 -!
ipset -A tcp_whitelist 197.234.240.0/22 -!
ipset -A tcp_whitelist 198.41.128.0/17 -!

# Drop ICMP
iptables -t mangle -A PREROUTING -p icmp -j DROP

# Protect HTTP/S ports
iptables -A PREROUTING -t raw -p tcp -m multiport --dports 80:85 -m set ! --match-set tcp_whitelist src -j DROP

# Protect shoutcast ports
iptables -A PREROUTING -t raw -p tcp -m multiport --dports 8000:8005 -m set ! --match-set udp_whitelist src -j DROP

# Protect SSH ports
iptables -A PREROUTING -t raw -p tcp -m multiport --dports 21:23 -m set ! --match-set tcp_whitelist src -j DROP

# Protect MYSQL ports
iptables -A PREROUTING -t raw -p tcp -m multiport --dports 3000:3500 -m set ! --match-set tcp_whitelist src -j DROP

# Invalid SA:MP Length
iptables -A PREROUTING -t raw -p udp --dport 7777 -m length --length 0:31 -j DROP
iptables -A PREROUTING -t raw -p udp --dport 7777 -m length --length 496:1024 -j DROP

# Protect SA:MP ports
iptables -A PREROUTING -t raw -p udp --dport 7777 -m u32 ! --u32 "28=0x53414d50" -m set ! --match-set udp_whitelist src -j DROP
```