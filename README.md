# scala-native-crypto

`java.security` Scala Native implementation based on OpenSSL

## Getting started

You need to add the dependency to your Scala Native project.

On SBT:

```scala
libraryDependencies += "com.github.lolgab" %%% "scala-native-crypto" % "x.y.z"
```

On Mill:

```scala
def ivyDeps = super.ivyDeps() ++ Agg(ivy"com.github.lolgab::scala-native-crypto::x.y.z")
```

You need also to install OpenSSL:

On Ubuntu:
```
sudo apt install libssl-dev
```

On Mac OS X (with Homebrew):
```
brew install openssl
```

And you need to have `libcrypto.[so|dylib]` in your linking path.

In Ubuntu it works out of the box since openssl is installed in the main
lib directory.

In Mac OS X you will need to add the path via `nativeLinkingOptions`.

On SBT:

```scala
nativeConfig ~= { c => c.withLinkingOptions(c.nativeLinkingOptions :+ "-L/usr/local/opt/openssl@3/lib") }
```

On Mill:

```scala
def nativeLinkingOptions = super.nativeLinkingOptions() ++ Seq("-L/usr/local/opt/openssl@3/lib")
```

## Implemented classes

- `java.security.MessageDigest`
