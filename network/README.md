
setup.sh による作成されるネットワーク

host1-veth1[10.0.0.1/24]----[10.0.0.254/24]router[10.0.1.254/24]---[10.0.1.1/24]host2-veth1

疎通確認

sudo ip netns exec host1 ping 10.0.1.1
sudo ip netns exec host2 ping 10.0.0.1
