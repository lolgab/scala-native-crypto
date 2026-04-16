package scalanativecrypto

import utest.{TestSuite, Tests, test, assert, assertThrows}

import java.math.BigInteger
import java.io.{ByteArrayInputStream, InputStream}
import java.util.{Collections, HashMap => JHashMap, Map => JMap}
import javax.security.auth.x500.X500Principal

class X500PrincipalSuite extends TestSuite {

  // Minimal valid ASN.1 DER encoding for DN "CN=Test":
  //   SEQUENCE {                 -- 30 0F
  //     SET {                    -- 31 0D
  //       SEQUENCE {             -- 30 0B
  //         OID 2.5.4.3          -- 06 03 55 04 03
  //         UTF8String "Test"    -- 0C 04 54 65 73 74
  //       }
  //     }
  //   }
  //
  // json repr:
  // {
  //   "seq": [
  //     {
  //       "set": [
  //         {
  //           "seq": [
  //             { "oid": { "oid": "2.5.4.3" } },
  //             { "utf8str": { "str": "Test" } }
  //           ]
  //         }
  //       ]
  //     }
  //   ]
  // }
  private val cnTest: Array[Byte] = new BigInteger(
    "300f310d300b06035504030c0454657374",
    16
  ).toByteArray()

  // Data source: https://kjur.github.io/jsrsasign/tool/tool_asn1encoder.html
  //
  // payload:
  //
  // {
  //   "seq": [
  //     {
  //       "set": [{
  //         "seq": [
  //         {"oid": {"oid": "2.5.4.6"}},
  //         {"prnstr": {"str": "EE"}}
  //         ]
  //       }]
  //     },
  //     {
  //       "set": [{
  //         "seq": [
  //           {"oid": {"oid": "2.5.4.10"}},
  //           {"utf8str": {"str": "AS Sertifitseerimiskeskus"}}
  //         ]
  //       }]
  //     },
  //     {
  //       "set": [{
  //         "seq": [
  //           {"oid": {"oid": "2.5.4.3"}},
  //           {"utf8str": {"str": "ESTEID-SK 2011"}}
  //         ]
  //       }]
  //     },
  //     {
  //       "set": [{
  //         "seq": [
  //           {"oid": {"oid": "1.2.840.113549.1.9.1"}},
  //           {"ia5str": {"str": "pki@sk.ee"}}
  //         ]
  //       }]
  //     }
  //   ]
  // }

  val estoniaID =
    new BigInteger(
      """
      3064310b300906035504061302454531223020060355040a0c
      19415320536572746966697473656572696d69736b65736b75
      733117301506035504030c0e4553544549442d534b20323031
      313118301606092a864886f70d0109011609706b6940736b2e
      6565
      """.stripIndent.split("\n").mkString.strip(),
      16
    ).toByteArray()

  val tests = Tests {

    test("constants") {
      assert(X500Principal.RFC1779 == "RFC1779")
      assert(X500Principal.RFC2253 == "RFC2253")
      assert(X500Principal.CANONICAL == "CANONICAL")
    }

    test("Constructor(String)") {
      assert(new X500Principal("CN=Test") != null)

      // multi-attribute DN RFC 2253 style without spaces"
      assert(
        new X500Principal("CN=Duke,OU=JavaSoft,O=Sun Microsystems,C=US") != null
      )

      // mutli same oid attributes
      assert(new X500Principal("DC=example,DC=com") != null)

      // with spaces
      assert(new X500Principal("UID=jsmith,    DC=example,   DC=net") != null)

      // with non ascii characters
      assert(new X500Principal("UID=用户, DC=net") != null)
    }

  }
}
