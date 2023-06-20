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
ln -sf /opt/nx/bin/python3nx /opt/nx/workers/bin
source /opt/nx/workers/bin/activate
pip install --upgrade /var/lib/nx/wheels/$wheel
set +x
for file in /opt/nx/workers/bin/*; do
  name=\$(basename \$file)
  [ -d /home/\$name ] || continue
  id \$name | grep -q '(nx-sniffers)' || continue
  echo \$PS4 sed -i 's/python3\$/python3nx/' \$file
  sed -i 's/python3\$/python3nx/' \$file
done
EOF
)

tag=$(echo $wheel | sed 's/-/ /g' | awk '{ print $2 }')
set -x
git tag -am $tag $tag
rm -f $wheel
