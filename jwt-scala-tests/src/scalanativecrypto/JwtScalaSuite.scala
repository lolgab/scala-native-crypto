package scalanativecrypto

import utest._
import pdi.jwt.{JwtUpickle, JwtAlgorithm, JwtClaim}
import java.time.Instant
import scala.util.{Failure, Success}

object JwtExampleSuite extends TestSuite {

  val tests = Tests {
    test("JWT should be correctly generated, signed, and verified") {
      // Define a secret key for signing the JWT
      val secretKey = "your-secret-key"
      // Create a claim (payload) for the JWT
      val claim = JwtClaim(
        content = """{"user":"exampleUser","role":"admin"}""",
        expiration = Some(Instant.now.plusSeconds(3600).getEpochSecond)
      )

      // Encode (sign) the JWT using HMAC SHA-256
      val token = JwtUpickle.encode(claim, secretKey, JwtAlgorithm.HS256)
      assert(token.nonEmpty)

      // Decode and verify the token
      JwtUpickle.decode(token, secretKey, Seq(JwtAlgorithm.HS256)) match {
        case Success(decodedClaim) =>

          assert(decodedClaim.content == claim.content)   // Check payload
          assert(decodedClaim.expiration == claim.expiration) // Check expiration
        case Failure(exception) =>
          sys.error(s"JWT verification failed with error: ${exception.getMessage}")
      }
    }
  }
}
