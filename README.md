# cip8-java

## Introduction
Implementation in Java CIP-8 parsing and validation (https://github.com/cardano-foundation/CIPs/tree/master/CIP-0008)

## Why is it useful?
If your server logic is in java, then you can use this library to process COSE signature and public key and do the following
- validate CIP-8 signature correctness

## Requirements
Java 17 LTS

## Building
```
mvn clean install
```

## Design Decisions
1. CIP Parser is strict, meaning that if CIP signature / key is invalid then after parsing none of the fields are available (null)
2. We try to minimise dependencies
3. We depend on Java17 because we assume that library will be used in new projects