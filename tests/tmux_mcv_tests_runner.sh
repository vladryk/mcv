#/bin/bash/

echo $1
SES_NAME='mcv_test'
tmux kill-session -t $SES_NAME
tmux new -d -s $SES_NAME 'sudo -i'
tmux rename-window 'jump'
tmux new-window -t $SES_NAME -n "default" "bash /opt/mcv-consoler/tests/test_groups_run.sh \"$1\""
