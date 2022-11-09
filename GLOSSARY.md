# Terms

- COSE public key - this is public key wrapped in COSE map.

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

- ED 25519 public key - represents Edwards-curve Digital Signature Algorithm (EdDSA 25519) key without COSE map wrapper (underlying cryptographic public key)

- address - represents a Cardano address serialised as a byte array. An actual address can be in Byron era / Ikarus and Shelley formats.

- 