package java.security

import java.util.Collections
import java.util.Objects.requireNonNull
import java.util.Properties
import java.util.{List => JList}
import java.util.{Map => JMap}
import java.util.{Set => JSet}

/**
 * Refs:
 *
 *   - https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/security/Provider.html
 *   - https://docs.oracle.com/en/java/javase/25/security/howtoimplaprovider.html
 */
abstract class Provider(
    private val name: String,
    private val versionStr: String,
    private val info: String
) extends Properties {

  requireNonNull(name)
  requireNonNull(versionStr)
  requireNonNull(info)
  require(name.nonEmpty && versionStr.nonEmpty && info.nonEmpty)

  // @volatile protected val defaults = _

  // @deprecated since JDK 9
  // @deprecated("Use `Provider(String, String, String)` instead instead", "JDK 9")
  // def this(name: String, version: Double, info: String) =
  //   this(name, version.toString, info)

  // @since JDK 9
  def configure(configArg: String): Provider

  // @since JDK 9
  def isConfigured(): Boolean

  def getName(): String

  // @deprecated since JDK 9
  // def getVersion(): Double = version

  // @since JDK 9
  def getVersionStr(): String

  def getInfo(): String

  override def toString(): String = s"${name} version ${versionStr}"

  def getService(`type`: String, algorithm: String): Provider.Service

  def getServices(): JSet[Provider.Service]

  protected def putService(s: Provider.Service): Unit

  protected def removeService(s: Provider.Service): Unit

}

object Provider {

  abstract class Service(
      private val provider: Provider,
      private val svcType: String,
      private val algorithm: String,
      private val className: String,
      private val aliases: JList[String],
      private val attributes: JMap[String, String]
  ) {
    requireNonNull(provider)
    requireNonNull(svcType)
    requireNonNull(algorithm)
    requireNonNull(className)
    require(svcType.nonEmpty && algorithm.nonEmpty && className.nonEmpty)

    private val svcAliases: JList[String] =
      if (aliases == null) JList.of()
      else Collections.unmodifiableList(aliases)
    private val serviceAttributes: JMap[String, String] =
      if (attributes == null) JMap.of()
      else Collections.unmodifiableMap(attributes)

    final def getType(): String = svcType

    final def getAlgorithm(): String = algorithm

    final def getProvider(): Provider = provider

    final def getClassName(): String = className

    final def getAttribute(name: String): String = {
      requireNonNull(name)
      require(name.nonEmpty)
      serviceAttributes.get(name)
    }

    def newInstance(constructorParameter: Object): Object

    def supportsParameter(parameter: Object): Boolean

    override def toString(): String = {
      val aliasStr =
        if (svcAliases.isEmpty) ""
        else s"  aliases: ${svcAliases}\r\n"
      val attrStr =
        if (serviceAttributes.isEmpty) ""
        else s"  attributes: ${serviceAttributes}\r\n"

      s"${provider.getName()}: ${svcType}.${algorithm} -> ${className}\r\n${aliasStr}${attrStr}"
    }
  }
}
