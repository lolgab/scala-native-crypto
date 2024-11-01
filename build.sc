import mill._, mill.scalalib._, mill.scalanativelib._, mill.scalanativelib.api._
import mill.scalalib.api.ZincWorkerUtil.isScala3
import mill.scalalib.publish._
import $ivy.`com.goyeau::mill-scalafix::0.3.2`
import com.goyeau.mill.scalafix.ScalafixModule
import $ivy.`de.tototec::de.tobiasroeser.mill.vcs.version::0.4.0`
import de.tobiasroeser.mill.vcs.version.VcsVersion
import $ivy.`com.lihaoyi::mill-contrib-buildinfo:`
import mill.contrib.buildinfo.BuildInfo

val scala212 = "2.12.20"
val scala213 = "2.13.15"
val scala3 = "3.3.4"
val scalaVersions = Seq(scala212, scala213, scala3)

// Disabled ScalafixModule since it adds SemanticDB files to artifacts
trait Shared
    extends CrossScalaModule /* with ScalafixModule */
    with ScalaNativeModule {
  def organization = "com.github.lolgab"
  def scalaNativeVersion = "0.5.5"

  def scalacOptions =
    super.scalacOptions() ++ (if (isScala3(crossScalaVersion)) Seq()
                              else Seq("-Ywarn-unused"))

  def scalafixIvyDeps = Agg(ivy"com.github.liancheng::organize-imports:0.6.0")
}

trait Test extends TestModule.Utest {
  override def ivyDeps = super.ivyDeps() ++ Agg(
    ivy"com.lihaoyi::utest::0.8.3"
  )
}

trait Publish extends PublishModule {
  def pomSettings =
    PomSettings(
      description =
        "Scala Native java.security implementation based on OpenSSL",
      organization = "com.github.lolgab",
      url = "https://github.com/lolgab/scala-native-crypto",
      licenses = Seq(License.`Apache-2.0`),
      versionControl =
        VersionControl.github(owner = "lolgab", repo = "scala-native-crypto"),
      developers = Seq(
        Developer("lolgab", "Lorenzo Gabriele", "https://github.com/lolgab")
      )
    )
  def publishVersion = VcsVersion.vcsState().format()
}
object `scala-native-crypto`
    extends Cross[ScalaNativeCryptoModule](scalaVersions)
trait ScalaNativeCryptoModule extends Shared with Publish {
  def compileModuleDeps = Seq(`scala-native-crypto-javalib-shims`())
  def scalacOptions = super.scalacOptions() ++ Seq(
    "-P:scalanative:genStaticForwardersForNonTopLevelObjects"
  )
}

object `scala-native-crypto-javalib-shims`
    extends Cross[ScalaNativeCryptoJavalibShimsModule](scalaVersions)
trait ScalaNativeCryptoJavalibShimsModule extends Shared with Publish

def jwtScalaSources = T {
  val dest = T.dest
  os.proc(
    "git",
    "clone",
    "--branch",
    "v10.0.2",
    "--depth",
    "1",
    "https://github.com/jwt-scala/jwt-scala.git",
    dest
  ).call()
  PathRef(dest)
}

object tests extends Module {
  object jvm extends Cross[TestsJvmModule](scalaVersions)
  trait TestsJvmModule extends CrossScalaModule with Test {
    override def millSourcePath = super.millSourcePath / os.up
  }

  object native extends Cross[TestsNativeModule](scalaVersions)
  trait TestsNativeModule
      extends CrossScalaModule
      with Shared
      with Test
      with TestScalaNativeModule {
    override def moduleDeps =
      super.moduleDeps ++ Seq(`scala-native-crypto`(crossScalaVersion))
    override def millSourcePath = super.millSourcePath / os.up
  }
}

object `jwt-scala-tests` extends Module {
  object jvm extends Cross[TestsJvmModule](scala3)
  trait TestsJvmModule extends CrossScalaModule with Test {
    override def millSourcePath = super.millSourcePath / os.up
  }

  object native extends Cross[TestsNativeModule](scala3)
  trait TestsNativeModule
      extends CrossScalaModule
      with Shared
      with Test
      with TestScalaNativeModule {
    override def moduleDeps =
      super.moduleDeps ++ Seq(`scala-native-crypto`(crossScalaVersion))
    override def millSourcePath = super.millSourcePath / os.up
    override def generatedSources = super.generatedSources() ++ Seq(
      PathRef(
        jwtScalaSources().path / "core" / "shared" / "src" / "main" / "scala"
      ),
      PathRef(
        jwtScalaSources().path / "json" / "upickle" / "shared" / "src" / "main" / "scala"
      ),
      PathRef(
        jwtScalaSources().path / "json" / "common" / "src" / "main" / "scala"
      )
    )
    override def ivyDeps = super.ivyDeps() ++ Agg(
      ivy"io.github.cquiroz::scala-java-time::2.6.0",
      ivy"com.lihaoyi::upickle::3.3.1"
    )
  }
}
