# cip8-java

[![Java CI with Maven](https://github.com/cardano-foundation/cip8-java/actions/workflows/maven.yml/badge.svg)](https://github.com/cardano-foundation/cip8-java/actions/workflows/maven.yml)

## Introduction
Partial implementation in Java CIP-8 parsing and validation (https://github.com/cardano-foundation/CIPs/tree/master/CIP-0008). This library is useful in situation where your project on the server is JVM based and you need to parse / validate CIP-8 signature and extract information encoded in it. In particular this library allows you to get / validate:
- validate CIP-8 signed envelopes using either embedded public key or explicitly supplied
- get message inside of the envolope
- get optionally stored Cardano address
- get ED 25519 public key and ED 25519 signature encoded in it
- get COSE payload (COSE wrapped message directly signed by the algorithm)

## Requirements
Java 17 LTS

## Building
```
mvn clean package
```

# Caveats / Notes
- library partially implements CIP-8 specification
- to keep dependencies minimal actual Cardano address is stored as byte array (you have to use other libraries, e.g. bloxbean to turn it into hex or bech32 format)
- parser is strict, meaning it won't be possible to extract / get various fields if a CIP-8 signature is invalid

# Contributing
