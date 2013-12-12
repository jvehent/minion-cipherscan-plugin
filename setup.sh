#!/bin/bash

set -x

# This script expects an active virtualenv

if [ -z "$VIRTUAL_ENV" ]; then
    echo "abort: no virtual environment active"
    exit 1
fi

case $1 in
    develop)
        python setup.py develop
        ;;
    install)
        python setup.py install
        find /usr/local/lib/python2.7/dist-packages -name cipherscan -type f -exec chmod +x {} \;
        find /usr/local/lib/python2.7/dist-packages -name openssl -type f -exec chmod +x {} \;
        ;;
esac
