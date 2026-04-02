# Enable EOS API
security pki key generate rsa 2048 self-signed.key
security pki certificate generate self-signed self-signed.crt key self-signed.key validity 365 parameters common-name fqdn

configure
management security
  ssl profile selfSignedSSLProfile
  certificate self-signed.crt key self-signed.key
!
management api http-commands
  protocol https ssl profile selfSignedSSLProfile
!
