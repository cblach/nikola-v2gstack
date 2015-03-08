============================================
Create self-signed SSL certficiate for EVSE:
============================================
1) Create .csr and .key:

openssl ecparam -name secp256r1 -genkey -out evse.key

openssl req -new -sha256 -key evse.key -out evse.csr -subj "/C=DK/ST=/L=Roskilde/O=DTU Risø/CN=evse"

2) Sign certificate:
openssl x509 -req -days 999999 -in evse.csr -signkey evse.key -out evse.crt

================
EV equivalent:
================
openssl ecparam -name secp256r1 -genkey -out ev.key
openssl req -new -sha256 -key ev.key -out ev.csr -subj "/C=DK/ST=/L=Roskilde/O=DTU Risø/CN=ev"
openssl x509 -req -days 999999 -in ev.csr -signkey ev.key -out ev.crt

================
Contract:
================
openssl ecparam -name secp256r1 -genkey -out contract.key
openssl req -new -sha256 -key contract.key -out contract.csr -subj "/C=DK/ST=/L=Roskilde/O=DTU Risø/CN=contract"
openssl x509 -req -days 999999 -in ev.csr -signkey contract.key -out contract.crt
