package scalanativecrypto.data

object CertExample0 {

  // $ openssl req -x509 -nodes -days 36500 -subj '/CN=Hey/O=Scala Native' -newkey rsa:512 -text -pubkey
  //
  // ..........++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
  // ...........++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
  // -----
  //
  // Certificate:
  //     Data:
  //         Version: 3 (0x2)
  //         Serial Number:
  //             05:91:9c:ce:ba:ca:11:37:77:1c:2d:a5:67:09:07:03:0b:73:0f:39
  //         Signature Algorithm: sha256WithRSAEncryption
  //         Issuer: CN=Hey, O=Scala Native
  //         Validity
  //             Not Before: Mar 27 03:03:39 2026 GMT
  //             Not After : Mar  3 03:03:39 2126 GMT
  //         Subject: CN=Hey, O=Scala Native
  //         Subject Public Key Info:
  //             Public Key Algorithm: rsaEncryption
  //                 Public-Key: (512 bit)
  //                 Modulus:
  //                     00:bc:26:69:bb:d1:5c:f9:16:55:54:25:eb:a7:55:
  //                     a4:75:a3:dd:0e:e3:16:e5:1b:12:d7:cf:09:0b:88:
  //                     13:74:7e:54:10:90:6e:aa:12:67:83:22:06:bb:01:
  //                     04:1d:8f:9f:8f:cc:fc:da:5b:d9:d6:75:ed:09:1b:
  //                     43:77:15:26:65
  //                 Exponent: 65537 (0x10001)
  //         X509v3 extensions:
  //             X509v3 Subject Key Identifier:
  //                 CE:A2:DA:0E:0F:61:56:82:9C:F8:43:87:A0:83:F7:7E:29:B6:CF:8C
  //             X509v3 Authority Key Identifier:
  //                 CE:A2:DA:0E:0F:61:56:82:9C:F8:43:87:A0:83:F7:7E:29:B6:CF:8C
  //             X509v3 Basic Constraints: critical
  //                 CA:TRUE
  //     Signature Algorithm: sha256WithRSAEncryption
  //     Signature Value:
  //         13:7f:30:8e:d8:8d:70:38:50:02:ee:29:f4:7c:f4:92:58:66:
  //         9e:5c:35:77:a1:6b:5d:ae:bf:77:b2:c1:7d:e7:62:b1:8a:eb:
  //         7d:60:cf:ac:ec:9e:8a:dc:d1:46:55:7d:df:55:84:52:65:13:
  //         d5:bf:d5:4c:64:6e:a0:da:d2:db

  val nonStripIndentPubKey =
    """
    -----BEGIN PUBLIC KEY-----
    MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALwmabvRXPkWVVQl66dVpHWj3Q7jFuUb
    EtfPCQuIE3R+VBCQbqoSZ4MiBrsBBB2Pn4/M/Npb2dZ17QkbQ3cVJmUCAwEAAQ==
    -----END PUBLIC KEY-----
    """

  val publicKey = nonStripIndentPubKey.stripIndent()

  val nonStripIndentCert =
    """
    -----BEGIN CERTIFICATE-----
    MIIBozCCAU2gAwIBAgIUBZGczrrKETd3HC2lZwkHAwtzDzkwDQYJKoZIhvcNAQEL
    BQAwJTEMMAoGA1UEAwwDSGV5MRUwEwYDVQQKDAxTY2FsYSBOYXRpdmUwIBcNMjYw
    MzI3MDMwMzM5WhgPMjEyNjAzMDMwMzAzMzlaMCUxDDAKBgNVBAMMA0hleTEVMBMG
    A1UECgwMU2NhbGEgTmF0aXZlMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALwmabvR
    XPkWVVQl66dVpHWj3Q7jFuUbEtfPCQuIE3R+VBCQbqoSZ4MiBrsBBB2Pn4/M/Npb
    2dZ17QkbQ3cVJmUCAwEAAaNTMFEwHQYDVR0OBBYEFM6i2g4PYVaCnPhDh6CD934p
    ts+MMB8GA1UdIwQYMBaAFM6i2g4PYVaCnPhDh6CD934pts+MMA8GA1UdEwEB/wQF
    MAMBAf8wDQYJKoZIhvcNAQELBQADQQATfzCO2I1wOFAC7in0fPSSWGaeXDV3oWtd
    rr93ssF952Kxiut9YM+s7J6K3NFGVX3fVYRSZRPVv9VMZG6g2tLb
    -----END CERTIFICATE-----
    """

  val cert = nonStripIndentCert.stripIndent()

}
