package scalanativecrypto

import utest.{TestSuite, Tests, test, assert, assertThrows}

import java.nio.charset.StandardCharsets.UTF_8
import java.security.cert.{CertificateFactory, X509Certificate}
import java.security.cert.CertificateException
import java.io.ByteArrayInputStream
import java.io.IOException

class CertificateFactorySuite extends TestSuite {
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

    test("CertificateFactory.generateCertificate") {
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

  }
}
