# cip8-java

## Introduction
Implementation in Java CIP-8 processing (https://github.com/cardano-foundation/CIPs/tree/master/CIP-0008)

## Why is it useful?
If your server logic is in java, then you can use this library to process COSE signature and public key and do the following
- validate correctness
- extract *original message* as byte[] | TEXT | HEX | BASE64
- extract *public key* (Ed25519) as byte[] | HEX | BASE6
- extract *signature* (Ed25519) as byte[] | HEX | BASE6
- extract *cardano address* as byte[] | HEX | BASE64
- extract *cose payload* (payload with cose wrapper) as byte[] | HEX | BASE6

## Requirements
Java 17 LTS

## Building
```
mvn clean install
```
