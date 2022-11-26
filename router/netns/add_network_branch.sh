ip netns add router3
ip netns add host3

ip link add name router1-router3 type veth peer name router3-router1
ip link add name router3-host3 type veth peer name host3-router3

ip link set router1-router3 netns router1
ip link set router3-router1 netns router3
ip link set router3-host3 netns router3
ip link set host3-router3 netns host3

ip netns exec router1 ip link set router1-router3 up
ip netns exec router1 ethtool -K router1-router3 rx off tx off

ip netns exec router3 ip addr add 192.168.3.2/24 dev router3-router1
ip netns exec router3 ip link set router3-router1 up
ip netns exec router3 ethtool -K router3-router1 rx off tx off
ip netns exec router3 ip route add default via 192.168.3.1
ip netns exec router3 ip addr add 192.168.4.1/24 dev router3-host3
ip netns exec router3 ip link set router3-host3 up
ip netns exec router3 ethtool -K router3-host3 rx off tx off
ip netns exec router3 sysctl -w net.ipv4.ip_forward=1

ip netns exec host3 ip addr add 192.168.4.2/24 dev host3-router3
ip netns exec host3 ip link set host3-router3 up
ip netns exec host3 ethtool -K host3-router3 rx off tx off
ip netns exec host3 ip route add default via 192.168.4.1
