# samp-firewall
Dedicated firewall for SA:MP

```shell
apt-get update
apt-get install -y gcc
apt-get install -y libpcap0.8*
apt-get install -y ipset
```

```shell
### Clear rules ###
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
iptables -D PREROUTING -t raw -p udp -m set ! --match-set samp_whitelist src -j DROP
ipset -X samp_whitelist -!

### SA:MP Firewall ###
ipset -N samp_whitelist hash:ip hashsize 16777216 maxelem 16777216 -!
iptables -A PREROUTING -t raw -p udp -m u32 ! --u32 "28=0x53414d50" -m set ! --match-set samp_whitelist src -j DROP

```
