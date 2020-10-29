#!/bin/sh

kdclist="kdc2.example.com" # "kdc2.example.com kdc3.example.com ..."
datapath="/var/kerberos/krb5kdc/replica_datatrans"

kdb5_util dump $datapath

for kdc in $kdclist
do
    kprop -f $datapath $kdc
done
