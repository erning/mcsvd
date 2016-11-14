#!/bin/bash
pushd `dirname $0` > /dev/null

GOMAXPROCS=0 ./mcsvd \
    :7070 \
    Certificate.crt.pem \
    PrivateKey.key.pem \
    CertificateBundle.crt.pem \
    AppleRootCA.crt.pem

popd > /dev/null
