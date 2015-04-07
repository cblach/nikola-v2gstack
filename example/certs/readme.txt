============================================
Create self-signed SSL certficiate for EVSE:
============================================
1) Create .csr and .key and Sign certificate:

openssl ecparam -name secp256r1 -genkey -out evse.key
openssl req -new -sha256 -key evse.key -out evse.csr -subj "/C=DK/ST=/L=Roskilde/O=DTU Risø/CN=evse"
openssl x509 -req -days 999999 -in evse.csr -signkey evse.key -out evse.pem

================
EV equivalent:
================
openssl ecparam -name secp256r1 -genkey -out ev.key
openssl req -new -sha256 -key ev.key -out ev.csr -subj "/C=DK/ST=/L=Roskilde/O=DTU Risø/CN=ev"
openssl x509 -req -days 999999 -in ev.csr -signkey ev.key -out ev.pem

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
