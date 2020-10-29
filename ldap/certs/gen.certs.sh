# RootCA

## Private Key
openssl genrsa -out rootca.key

## CSR data
cat > rootca.csr.conf << EOF
[ req ]
default_bits            = 2048
default_md              = sha256
distinguished_name      = req_distinguished_name
prompt                  = no
encrypt_key             = no

[ req_distinguished_name ]
countryName                     = "KR"
stateOrProvinceName             = "Seoul"
localityName                    = "Seoul"
0.organizationName              = "MyCompany"
organizationalUnitName          = "TopUnit"
commonName                      = "RootCA"
EOF

## CSR
openssl req -new -key rootca.key -config rootca.csr.conf -out rootca.csr

## Certification
openssl req -x509 -sha256 -nodes -days 364 -key rootca.key -in rootca.csr -out rootca.crt

###

# LDAP Provider

## Private Key
openssl genrsa -out example.com.key

## CSR data
cat > example.com.csr.conf << EOF
[ req ]
default_bits            = 2048
default_md              = sha256
distinguished_name      = req_distinguished_name
prompt                  = no
encrypt_key             = no

[ req_distinguished_name ]
countryName                     = "KR"
stateOrProvinceName             = "Seoul"
localityName                    = "Seoul"
0.organizationName              = "MyCompany"
organizationalUnitName          = "MyUnit"
commonName                      = "*.example.com"
EOF

## CSR
openssl req -new -key example.com.key -config example.com.csr.conf -out example.com.csr

## Certification
openssl x509 -req -in example.com.csr -CAcreateserial -CA rootca.crt -CAkey rootca.key -out example.com.crt

###

# Replicator

## Private Key
openssl genrsa -out replicator.key

## CSR data
cat > replicator.csr.conf << EOF
[ req ]
default_bits            = 2048
default_md              = sha256
distinguished_name      = req_distinguished_name
prompt                  = no
encrypt_key             = no

[ req_distinguished_name ]
countryName                     = "KR"
stateOrProvinceName             = "Seoul"
localityName                    = "Seoul"
0.organizationName              = "MyCompany"
organizationalUnitName          = "MyUnit"
commonName                      = "replicator"
EOF

## CSR
openssl req -new -key replicator.key -config replicator.csr.conf -out replicator.csr

## Certification
openssl x509 -req -in replicator.csr -CAcreateserial -CA rootca.crt -CAkey rootca.key -out replicator.crt
