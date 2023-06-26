#!/bin/sh

set -euo pipefail

wheel=$(ls -1 nx_workers-*.whl | tail -n 1)
remote=nx-deploy@slice

rsync -a $wheel $remote:/var/lib/nx/wheels
ssh $remote bash -s < <(
cat <<EOF
export PS4="-|\$USER@\$HOSTNAME| "
set -exuo pipefail
[ -f /opt/nx/workers/bin/activate ] || python3 -m venv /opt/nx/workers
/opt/nx/workers/bin/pip install --upgrade /var/lib/nx/wheels/$wheel
EOF
)

tag=$(echo $wheel | sed 's/-/ /g' | awk '{ print $2 }')
set -x
git tag -am $tag $tag
rm -f $wheel
