#!/bin/bash
echo "Launching Database "
echo "  /opt/muppy/appserver-sunray18/bin/mpy_init_db.sh"
echo -e "\n"
/opt/muppy/appserver-sunray18/bin/sunray-srvr -i sunray_core  --without-demo=all --stop-after-init