============================================
Create self-signed SSL certficiate for EVSE:
============================================
1) Create .csr and .key, Sign with root certificate and concatenate certificates to a chain:

openssl ecparam -name secp256r1 -genkey -out evse.key
openssl req -new -sha256 -key evse.key -out evse.csr -subj "/C=DK/ST=/L=Roskilde/O=DTU Risø/CN=evse"

openssl ca -keyfile root/v2g/keys/v2g.key \
    -cert root/v2g/certs/v2g.pem \
    -extensions usr_cert -notext -md sha256 -config ca/v2g/openssl.cfg \
    -in evse.csr -out evse.pem -outdir . -verbose
openssl verify -CAfile root/v2g/certs/v2g.pem evse.pem
cat root/v2g/certs/v2g.pem >> evse.pem
================
EV equivalent:
================
openssl ecparam -name secp256r1 -genkey -out ev.key
openssl req -new -sha256 -key ev.key -out ev.csr -subj "/C=DK/ST=/L=Roskilde/O=DTU Risø/CN=ev"
openssl ca -keyfile root/oem/keys/oem.key \
    -cert root/oem/certs/oem.pem \
    -extensions usr_cert -notext -md sha256 -config ca/oem/openssl.cfg \
    -in ev.csr -out ev.pem -outdir . -verbose


================
Mobility operator root certificate (contract root):
================
openssl ecparam -name secp256r1 -genkey -out root/mobilityop/keys/mobilityop.key
openssl req -new -sha256 -key root/mobilityop/keys/mobilityop.key \
    -out root/mobilityop/certs/mobilityop.pem \
    -subj "/C=DK/ST=/L=Roskilde/O=DTU Risø/CN=Mobility operator root" \
    -days 999999 -x509

================
Contract signed by mobility operator root:
================
openssl ecparam -name secp256r1 -genkey -out contract.key
openssl req -new -sha256 -key contract.key -out contract.csr -subj "/C=DK/ST=/L=Roskilde/O=DTU Risø/CN=contract"
openssl ca -keyfile root/mobilityop/keys/mobilityop.key \
    -cert root/mobilityop/certs/mobilityop.pem \
    -extensions usr_cert -notext -md sha256 -config ca/mobilityop/openssl.cfg \
    -in contract.csr -out contract.pem -outdir . -verbose

openssl verify -CAfile root/mobilityop/certs/mobilityop.pem contract.pem
