# ipsecCertCheck
ipsecCertCheck will check a certificate chain using the same OSX APIs as the built-in IPSec
VPN client on OSX. You can use this program to debug VPN connection failures that have the following log messages:
```
eval result = kSecTrustResultRecoverableTrustFailure
```

# Usage
```
ipsecCertCheck vpn-server-address leaf-certificate.der [ intermediate-ca-cert.der ... ] root-ca-cert.der
```

# Hints
To convert a DER file to a PEM:
```
openssl x509 -in cert.pem -inform PEM -outform DER -out cert.der
```


# Examples:
Subject in VPN server's certificate: vpn-endpoint.foo.com

Server Address specified in connection config: 172.31.0.12

To debug:
```
sudo ipsecCertCheck 172.31.0.12 vpn-server.der int-ca.der ca.der
```

Output:
```
---------------------------
title : vpn-endpoint.foo.com
error : Host name mismatch
---------------------------
title : Foo Intermediate CA
---------------------------
title : Foo
---------------------------
Cert failed check!!!
```