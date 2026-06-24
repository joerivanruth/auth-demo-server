#!/bin/bash

set -e -x

MONET_PRINCIPAL="monetdb/$(hostname -f)@GITHUB.CI"

# Install the packages
apt-get update
apt-get install -y krb5-admin-server krb5-kdc krb5-user



# Create /etc/krb5.conf
tee /etc/krb5.conf >/dev/null <<'EOF'
[libdefaults]
        default_realm = GITHUB.CI
        kdc_timesync = 1
        ccache_type = 4
        forwardable = true
        proxiable = true
        rdns = false
[realms]
        GITHUB.CI = {
                kdc = localhost:88
                admin_server = localhost:749
        }
# omitted [domain_realm]
EOF


# Create /etc/krb5kdc/kdc.conf and the stuff in /var
mkdir -p /etc/krb5kdc
sudo mkdir -p /var/lib/krb5kdc
sudo chmod 755 /var/lib/krb5kdc
tee /etc/krb5kdc/kdc.conf >/dev/null <<'EOF'

[kdcdefaults]
    kdc_ports = 88
    kdc_tcp_ports = 88

[realms]
    GITHUB.CI = {
        database_name = /var/lib/krb5kdc/principal
        default_principal_flags = +preauth
    }

EOF


# Initialize the realm
echo -e "password\npassword" | sudo kdb5_util create -s -r GITHUB.CI

systemctl restart krb5-kdc krb5-admin-server

kadmin.local <<EOF
addprinc -pw password testuser
addprinc -randkey $MONET_PRINCIPAL
ktadd -k /etc/monetdb.keytab $MONET_PRINCIPAL
EOF

chmod 0755 /etc/monetdb.keytab


