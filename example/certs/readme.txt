Create self-signed SSL certficiate:

1) Create .csr and .key:

openssl ecparam -name secp521r1 -genkey -param_enc explicit -out evse.key

openssl req -new -sha256 -key evse.key -out evse.csr -subj "/C=DK/ST=/L=Roskilde/O=DTU Risø/CN=evse"

2) Sign certificate:
openssl x509 -req -days 14609688 -in evse.csr -signkey evse.key -out evse.crt



EV equivalent:
# openssl req -new -newkey rsa:4096 -nodes -out ev.csr -keyout ev.key -subj "/C=DK/ST=/L=Roskilde/O=DTU Risø/CN=ev"

# openssl x509 -req -days 365 -in ev.csr -signkey ev.key -out ev.crt
