# メモ

Linux 標準のルータ機能を無効化する
`ip netns exec router1 sysctl -w net.ipv4.ip_forward=0`
