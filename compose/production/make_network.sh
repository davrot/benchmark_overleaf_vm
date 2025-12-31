sudo docker network create overleaf-network
snetz=$(sudo docker network inspect overleaf-network -f '{{range .IPAM.Config}}{{.Subnet}}{{end}}')
nid=`sudo docker network ls | grep overleaf-network | awk '{print $1}'`

sudo ufw allow in on br-$nid
sudo ufw route allow in on br-$nid
sudo ufw route allow out on br-$nid
sudo iptables -t nat -A POSTROUTING ! -o br-$nid -s $snetz -j MASQUERADE

