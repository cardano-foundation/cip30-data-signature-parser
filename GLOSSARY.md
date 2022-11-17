# Terms

- DataSignature - consists of COSE_Sign1 and COSE_Key

- COSE_Sign1 - signed COSE envelope containing message, optional cardano address and public key

- COSE_Key - a public key - this is public key wrapped in COSE map, in typical scenarios COSE Signature contains public key
 but in some cases one can explicitly pass COSE public key (e.g. when wallet doesn't store COSE public key)

  Example, given the following COSE public key: 'a40101032720062158202f1867873147cf53c442435723c17e83beeb8e2153851cd73ccfb1b5e68994a4'
  we can see that it deserialises into the following COSE map:

```
    {
      1: 1,
      3: -8,
     -1: 6,
     -2: h'2f1867873147cf53c442435723c17e83beeb8e2153851cd73ccfb1b5e68994a4',
    }
```

  Under index '-2' the actual  ED 25519 public key is stored in HEX format.

- message - the actual byte array / string / text signed by the wallet

- address - represents a Cardano address serialised as a byte array. An actual address can be in Byron era / Ikarus and Shelley formats.

- ED 25519 public key - represents Edwards-curve Digital Signature Algorithm (EdDSA 25519) key without COSE wrapper (underlying cryptographic public key)

- ED 25519 signature - represents Edwards-curve signature without COSE wrapper (EdDSA 25519) (underlying cryptographic signature)

- COSE Payload - this is cose wrapped message that will be directly signed by ED 25519 algorithm
