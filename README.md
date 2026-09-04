# **GCrypt** - A lightweight C++ E2EE library

![C++23](https://img.shields.io/badge/language-C++23-blue.svg)

**Gcrypt** is a lightweight cryptographic library C++ used to perform **E2E** Encryption, specifically an implementation of the [Signal Protocol](https://en.wikipedia.org/wiki/Signal_Protocol). As well as this, **Gcrypt** also offers a nice wrapper interface with key generation & manipultation for its [implemented protocols and algorithms](#implemented-protocols).



## Version
This project is in its Alpha stages and only supports a handful of features as of writing this. Upon completion of the protocol, documentation will be added for the **C++ implementation** and [external implementation bridges](#cross-platform-support).

## Implemented protocols

Gcrypt uses the following algorithms (contained in the [Signal protocol spec](https://signal.org/docs/)):

- [X25519 (Curve 25519) algorithm](https://en.wikipedia.org/wiki/Curve25519)
- [Ed25519 algorithm](https://en.wikipedia.org/wiki/EdDSA)
- [SHA-512](https://en.wikipedia.org/wiki/SHA-2)
- [HKDF](https://en.wikipedia.org/wiki/HKDF)
- [ML-KEM (Kyber)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf)
- [XedDSA/VXEdDSA Protocols](https://signal.org/docs/specifications/xeddsa/)

## Depedencies & Requirements

Currently, **Gcrypt** relies on:
- [mlkem-native-**2.0.0**](https://github.com/pq-code-package/mlkem-native) 
- [libsodium-**1.0.22**](https://libsodium.gitbook.io/doc)

## Design

Gcrypt's design is centered around reducing the complexity of the [Signal protocol](https://en.wikipedia.org/wiki/Signal_Protocol).
Although fully documented, no well known lightweight implementation exists for this protocol other than the official signal protocol git, and their outdated `C` implementation. This software is utilises modern C++ templates and features to bring a modularized approach to the problem of **E2EE (End to End Encryption)**.

The design also allows developers to use cryptographic features such as:

- Key Generation / Modification
- Hashing
- Performing any of the [Implemented Protocols](#implemented-protocols)

## Licence
Since this is developed and maintained solely by me, there is no licence. Enjoy !

## Make

CMake is configured to output the code as a `.lib`. It is also configured to fetch **mlkem-native** if not present. If downloaded already, place them in the folder structure:

```
/dependencies
    /libsodium
        /include
            /sodium
            sodium.h
        /lib
            libsodium.lib
            libsodium.pdf
/src
    ...
```

## Issues

Any issues found with the implementation can be registered through the [issues page](https://github.com/TBCMDev/gcrypt/issues).

## Cross platform support

### Java / Kotlin

The [java](https://github.com/TBCMDev/gcrypt/tree/ext/java) folder in the ext directory contains files that can be used to interface the gcrypt API with java/kotlin. Currently, no docs are available; the file contains important wrappers that mimic the structure of the protocol's high level functions only.

### Customizing

The following macros can be defined:

#### `GCRYPT_NOSTORE`
If defined, no storage implementation will be included in the build. This allows for people using Gcrypt for other cryptographic reasons.
For people using gcrypt for a complete signal implementation, they should not define this macro and instead implement the functions found in `sessions.hpp` to allow for in memory and disk storage of sessions and keys.

#### `MLK_CONFIG_PARAMETER_SET`

Defines the size of the post quantum keys to generate via the MLK algorithm.