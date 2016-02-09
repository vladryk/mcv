#/bin/bash/

declare -a arr=$1
sudo sed -i "/\[basic\]/acontroller_ip=${arr[0]}" /etc/mcv/mcv.conf
sudo sed -i "/\[basic\]/ainstance_ip=${arr[1]}" /etc/mcv/mcv.conf
sudo sed -i "/\[basic\]/aos_username=${arr[2]}" /etc/mcv/mcv.conf
sudo sed -i "/\[basic\]/aos_tenant_name=${arr[3]}" /etc/mcv/mcv.conf
sudo sed -i "/\[basic\]/aos_password=${arr[4]}" /etc/mcv/mcv.conf
sudo sed -i "/\[basic\]/aauth_endpoint_ip=${arr[5]}" /etc/mcv/mcv.conf
sudo sed -i "/\[basic\]/anailgun_host=${arr[6]}" /etc/mcv/mcv.conf
sudo sed -i "/\[basic\]/acluster_id=${arr[7]}" /etc/mcv/mcv.conf
sudo sed -i "s/version=6.1/version=${arr[8]}/" /etc/mcv/mcv.conf
sudo sed -i "s/private_endpoint_ip=192.168.0.2/private_endpoint_ip=${arr[9]}/" /etc/mcv/mcv.conf
sudo mcvconsoler --run custom resources >> /tmp/cli_output.log
sudo echo 'resources: ' $? >> /tmp/test_result.log
sudo mcvconsoler --run custom default >> /tmp/cli_output.log
sudo echo 'default: ' $? >> /tmp/test_result.log
sudo mcvconsoler --run custom shaker >> /tmp/cli_output.log
sudo echo 'shaker: ' $? >> /tmp/test_result.log
sudo mcvconsoler --run custom smoke >> /tmp/cli_output.log
sudo echo 'smoke: ' $? >> /tmp/test_result.log
