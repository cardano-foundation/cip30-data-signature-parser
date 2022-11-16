# cip8-java

[![Java CI with Maven](https://github.com/cardano-foundation/cip8-java/actions/workflows/maven.yml/badge.svg)](https://github.com/cardano-foundation/cip8-java/actions/workflows/maven.yml)

## Introduction
Partial implementation in Java CIP-8 / CIP-30 parsing and validation (https://github.com/cardano-foundation/CIPs/tree/master/CIP-0008). This library is useful in situation where your project is JVM based and you need to parse / validate CIP-30 signature / key and extract information encoded in it.


## Features
In particular this library allows you to get / validate:
- validate CIP-8 / CIP-30 signed envelopes using either embedded public key or explicitly supplied
- get message inside of the envolope
- get optionally stored Cardano address
- get ED 25519 public key and ED 25519 signature encoded in it
- get COSE payload (COSE wrapped message directly signed by the algorithm)
- compatible with Sundae Swap's governance system (ED 25519 public key and ED 25519 signature as well as COSE payload) 

## Requirements
Java 17 LTS or greather

## Building
```
https://github.com/cardano-foundation/cip8-java
mvn clean package
```

## Example Usage
```java
        var sig = "84582aa201276761646472657373581de1b83abf370a14870fdfd6ccb35f8b3e62a68e465ed1e096c5a6f5b9d6a166686173686564f4565468697320697320612074657374206d657373616765584042e2bfc4e1929769a0501b884f66794ae3485860f42c01b70fac37f75e40af074c6b2a61b04c6cf8a493c0dced1455b4f1129dbf653ad9801c52ce49ff6d5a0e";
        var key = "a40101032720062158202f1867873147cf53c442435723c17e83beeb8e2153851cd73ccfb1b5e68994a4";

        var p = new CIP8Parser(sig, key);

        var result = p.parse();

        System.out.println("is valid?: " + result.isValid());

        System.out.println("address: " + com.bloxbean.cardano.client.address.util.AddressUtil.bytesToAddress(result.getAddress().orElseThrow()));
        System.out.println("message: " + result.getMessage(TEXT));
```
produces
```
is valid?: true
address: stake1uxur40ehpg2gwr7l6mxtxhut8e32drjxtmg7p9k95m6mn4s0tdy6k
message: This is a test message
```


# Caveats / Notes
- library partially implements CIP-8 specification
- to keep dependencies minimal actual Cardano address is stored as byte array (you have to use other libraries, e.g. bloxbean to turn it into hex or bech32 format)
- parser is strict, meaning it won't be possible to extract / get various fields if a CIP-8 signature is invalid
- even though CIP-8 specification allows for signing with multiple keys this library supports only scenario where signing was done with one key (COSESign1)

