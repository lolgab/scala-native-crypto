package scalanativecrypto

import utest.{TestSuite, Tests, test, assert, assertThrows}

import java.nio.charset.StandardCharsets.UTF_8
import java.security.cert.{CertificateFactory, X509Certificate}
import java.security.cert.CertificateException
import java.io.{ByteArrayInputStream, FileInputStream}
import java.io.IOException

class CertificateFactorySuite extends TestSuite {

  val resourceDir = sys.env("MILL_TEST_RESOURCE_DIR")

  val tests = Tests {

    test("CertificateFactory.getInstance") {
      val cf = CertificateFactory.getInstance("X.509")
      assert(cf.getType() == "X.509")
    }

    test("generateCertificate should fail in non indent format cert") {
      val cf = CertificateFactory.getInstance("X.509")

      assertThrows[CertificateException] {
        cf.generateCertificate(
          new ByteArrayInputStream(
            data.CertExample0.nonStripIndentCert.getBytes(UTF_8)
          )
        )
      }
    }

    test("CertificateFactory.generateCertificate via ByteArrayInputStream") {
      val cf = CertificateFactory.getInstance("X.509")
      val cert = cf.generateCertificate(
        new ByteArrayInputStream(data.CertExample0.cert.getBytes(UTF_8))
      )
      assert(cert.isInstanceOf[X509Certificate])

      val x509Cert = cert.asInstanceOf[X509Certificate]

      val dnames = x509Cert
        .getSubjectX500Principal()
        .getName()
        .split(",")
        .map(_.trim)
        .toSet
      assert((dnames -- Set("O=Scala Native", "CN=Hey")).isEmpty)
    }

    test("CertificateFactory.generateCertificate via FileInputStream") {
      val cf = CertificateFactory.getInstance("X.509")
      val cert = cf.generateCertificate(
        new FileInputStream(
          s"${resourceDir}/x509-cert-pem-noenc/certificate.pem"
        )
      )
      assert(cert.isInstanceOf[X509Certificate])

      val x509Cert = cert.asInstanceOf[X509Certificate]

      val dnames = x509Cert
        .getSubjectX500Principal()
        .getName()
        .split(",")
        .map(_.trim)
        .toSet
      assert((dnames -- Set("O=Scala Native", "CN=Hey")).isEmpty)
    }

    // generateCertificates

    // test("CertificateFactory.generateCertificates") {
    //   val cf = CertificateFactory.getInstance("X.509")
    //   val certs = cf.generateCertificates(
    //     new FileInputStream(
    //       s"${resourceDir}/pkcs12-chain-case-1/bundle.cert.pem"
    //     )
    //   )
    //   assert(certs.size() == 3)
    //   certs.forEach(c => assert(c.isInstanceOf[X509Certificate]))
    // }
  }
}
