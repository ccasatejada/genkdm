##!/bin/bash
#
#set -e
#
## 📁 Dossiers et fichiers
#ROOT_DIR="./certs"
#mkdir -p "$ROOT_DIR"
#
#ROOT_CONF="$ROOT_DIR/openssl_root.cnf"
#INTER_CONF="$ROOT_DIR/openssl_inter.cnf"
#SERVER_CONF="$ROOT_DIR/openssl_server.cnf"
#
#CA_KEY="$ROOT_DIR/ca_private_key.pem"
#CA_CERT="$ROOT_DIR/ca_cert.pem"
#
#INTERMEDIATE_KEY="$ROOT_DIR/intermediate_private_key.pem"
#INTERMEDIATE_CSR="$ROOT_DIR/intermediate.csr"
#INTERMEDIATE_CERT="$ROOT_DIR/intermediate_cert.pem"
#
#SERVER_KEY="$ROOT_DIR/server_private_key.pem"
#SERVER_CSR="$ROOT_DIR/server.csr"
#SERVER_CERT="$ROOT_DIR/server_cert.pem"
#
#FULL_CERT_CHAIN="$ROOT_DIR/full_cert_chain.pem"
#
#DAYS=365
#
## 🔧 Génération CA Root
#echo "🔧 Génération CA Root..."
#openssl genpkey -algorithm RSA -out $CA_KEY -pkeyopt rsa_keygen_bits:2048
#
#openssl req -new -x509 \
#  -key ca_key.pem \
#  -out ca_cert.pem \
#  -config ./openssl.cnf \
#  -extensions v3_ca \
#  -subj "/CN=Root.CA/O=RootOrg/dnQualifier=xyz123" \
#  -days 365
#
## 🪜 Génération Intermédiaire
#echo "🔧 Génération CA Intermédiaire..."
#openssl genpkey -algorithm RSA -out $INTERMEDIATE_KEY -pkeyopt rsa_keygen_bits:2048
#openssl req -new -key $INTERMEDIATE_KEY -out $INTERMEDIATE_CSR -config "$INTER_CONF"
#
#openssl x509 -req -in $INTERMEDIATE_CSR -CA $CA_CERT -CAkey $CA_KEY -CAcreateserial \
#    -out $INTERMEDIATE_CERT -days $DAYS -sha256 \
#    -extfile $INTER_CONF \
#    -extensions v3_inter
#
## 🖥️ Génération Certificat Machine
#echo "🔧 Génération certificat device (serveur)..."
#openssl genpkey -algorithm RSA -out $SERVER_KEY -pkeyopt rsa_keygen_bits:2048
#openssl req -new -key $SERVER_KEY -out $SERVER_CSR -config "$SERVER_CONF"
#
#openssl x509 -req -in $SERVER_CSR -CA $INTERMEDIATE_CERT -CAkey $INTERMEDIATE_KEY -CAcreateserial \
#    -out $SERVER_CERT -days $DAYS -sha256 \
#    -extfile $SERVER_CONF \
#    -extensions v3_req
#
## 🔖 Ajout Thumbprint SMPTE (dnQualifier)
#calculate_smpte_thumbprint() {
#    openssl x509 -pubkey -noout -in "$1" |
#        openssl pkey -pubin -outform der |
#        openssl dgst -sha1 -binary |
#        base64
#}
#
## 👇 Ajout du thumbprint dans le DN (à titre illustratif, ce n’est pas une vraie modif X.509)
#add_smpte_thumbprint_to_subject() {
#    cert_file=$1
#    thumbprint=$(calculate_smpte_thumbprint "$cert_file")
#    echo "🔖 Thumbprint (dnQualifier): $thumbprint"
#}
#
#add_smpte_thumbprint_to_subject $CA_CERT
#add_smpte_thumbprint_to_subject $INTERMEDIATE_CERT
#add_smpte_thumbprint_to_subject $SERVER_CERT
#cat $SERVER_CERT $INTERMEDIATE_CERT $CA_CERT > $FULL_CERT_CHAIN
#
## ✅ Résumé
#echo ""
#echo "✅ Certificats générés avec succès :"
#echo "CA Certificate:             $CA_CERT"
#echo "Intermediate Certificate:   $INTERMEDIATE_CERT"
#echo "Device Certificate:         $SERVER_CERT"
#echo "Chain certificates:         $FULL_CERT_CHAIN"
#
