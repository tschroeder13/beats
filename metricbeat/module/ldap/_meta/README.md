# Genrate certificates for ldaps
openssl genrsa -out domain.key 2048
openssl req -key domain.key -new -out domain.csr
openssl x509 -signkey domain.key -in domain.csr -req -days 365 -out domain.crt
openssl req -x509 -sha256 -days 1825 -newkey rsa:2048 -keyout rootCA.key -out rootCA.crt
openssl x509 -req -CA rootCA.crt -CAkey rootCA.key -in domain.csr -out domain.crt -days 365 -CAcreateserial -extfile domain.ext
