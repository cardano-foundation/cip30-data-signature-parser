# Java CIP-30 Data Signature Parser and Validator


[![Build](https://github.com/cardano-foundation/cip30-data-signature-parser/actions/workflows/maven-build.yml/badge.svg)](https://github.com/cardano-foundation/cip30-data-signature-parser/actions/workflows/maven-build.yml)
[![CodeQL](https://github.com/cardano-foundation/cip30-data-signature-parser/actions/workflows/codeql.yml/badge.svg)](https://github.com/cardano-foundation/cip30-data-signature-parser/actions/workflows/codeql.yml)
![Maven Central](https://img.shields.io/maven-central/v/org.cardanofoundation/cip30-data-signature-parser)
[![License](https://img.shields.io:/github/license/cardano-foundation/cip30-data-signature-parser?label=license)](https://github.com/cardano-foundation/cip30-data-signature-parser/blob/master/LICENSE)
![GitHub tag (latest by date)](https://img.shields.io/github/v/tag/cardano-foundation/cip30-data-signature-parser)
[![javadoc](https://javadoc.io/badge2/org.cardanofoundation/cip30-data-signature-parser/javadoc.svg)](https://javadoc.io/doc/org.cardanofoundation/cip30-data-signature-parser)
![Discord](https://img.shields.io/discord/1022471509173882950)

## Introduction
Implementation in Java of CIP-30 Data Signature Parser and Validator (https://github.com/cardano-foundation/CIPs/tree/master/CIP-0030).
This library is useful in situation where your project is JVM based and you need to parse / validate CIP-30 data signature and extract information encoded in it.

## Features
In particular this library allows you to get / validate:
- validate CIP-30 data signed envelop (DataSignature) using either embedded public key or explicitly supplied key (CIP-30 data signature should contain public key)
- get message from the data signature envelope
- get stored Cardano address
- get ED 25519 public key and ED 25519 signature encoded in it
- get COSE payload (COSE wrapped message directly signed by the algorithm)
- library makes it easy to extract (ED 25519 public key and ED 25519 signature as well as COSE payload) 

## External

- [GLOSSARY.md](GLOSSARY.md)
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)


## Requirements
Java 17 LTS or greater

## Building
```
git clone https://github.com/cardano-foundation/cip30-data-signature-parser
cd cip30-data-signature-parser
mvn clean package
```

## Dependency
```xml
<dependency>
    <groupId>org.cardanofoundation</groupId>
    <artifactId>cip30-data-signature-parser</artifactId>
    <version>0.0.10</version>
</dependency>
```

## Example Usage
```java
var sig = "84582aa201276761646472657373581de1b83abf370a14870fdfd6ccb35f8b3e62a68e465ed1e096c5a6f5b9d6a166686173686564f4565468697320697320612074657374206d657373616765584042e2bfc4e1929769a0501b884f66794ae3485860f42c01b70fac37f75e40af074c6b2a61b04c6cf8a493c0dced1455b4f1129dbf653ad9801c52ce49ff6d5a0e";
var key = "a40101032720062158202f1867873147cf53c442435723c17e83beeb8e2153851cd73ccfb1b5e68994a4";

var verifier = new CIP30Verifier(sig, key);

var verificationResult = verifier.verify();

System.out.println("is valid?: " + verificationResult.isValid());

System.out.println("Optional address(bech32):" + verificationResult.getAddress(AddressFormat.TEXT).orElseThrow());

System.out.println("Message: " + result.getMessage(TEXT));
```
produces
```
is valid?: true
Optional address(bech32):: stake1uxur40ehpg2gwr7l6mxtxhut8e32drjxtmg7p9k95m6mn4s0tdy6k
message: This is a test message
```

# Caveats / Notes
- parser is strict, meaning it won't be possible to extract / get various fields if a CIP-30 signature is invalid, alternatively one can develop one with lenient parsing.

