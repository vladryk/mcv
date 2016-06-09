#/bin/bash/

echo $1 $2 $3 >creds.log
TEST_NAME=$1
declare -a credentials=$2
declare -a test_suite=$3
for i in ${credentials[@]}
do
    name=$(echo $i | awk -F"=" {'print $1'})
    sudo sed -i "s/#$name.*/$i/g" /etc/mcv/mcv.conf
done

if [ $TEST_NAME == "small" ]
then
    sudo sed -i -e '1 s/^/[custom_test_group_small]\n/;' /etc/mcv/mcv.conf
    for testname in ${test_suite[@]}
        do
            sudo sed -i "/\[custom_test_group_small\]/a$testname" /etc/mcv/mcv.conf
            sudo mcvconsoler --run group small >> /tmp/small.log
            sudo echo "$testname $?" >> /tmp/test_result.log
            sudo sed -i 2d /etc/mcv/mcv.conf
        done
else
    for testname in ${test_suite[@]}
        do
            sudo mcvconsoler --run group $testname >> /tmp/cli_output.log
            sudo echo "$testname $?" >> /tmp/test_result.log
        done
fi
