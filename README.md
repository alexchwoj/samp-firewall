# hyaxe-samp-firewall
debes firewall pa samp

apt-get update
apt-get install -y gcc
apt-get install -y libpcap0.8*

Enable address:
iptables -I INPUT -s address/32 -j ACCEPT

Disable address:
iptables -D INPUT -s address/32 -j ACCEPT

Disable UDP:
iptables -A INPUT -p udp -j DROP

iptables -I INPUT -s 192.95.10.233/32 -j ACCEPT