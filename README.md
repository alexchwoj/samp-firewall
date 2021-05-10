# hyaxe-samp-firewall
debes firewall pa samp

Enable address:
iptables -I INPUT -s address/32 -j ACCEPT

Disable address:
iptables -D INPUT -s address/32 -j ACCEPT

Disable UDP:
iptables -A INPUT -p udp -j DROP