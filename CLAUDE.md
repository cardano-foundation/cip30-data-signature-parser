# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Common Commands

### Build and Test
- **Build project**: `./mvnw clean package`
- **Run all tests**: `./mvnw test`
- **Run specific test class**: `./mvnw test -Dtest=CIP30VerifierTest`
- **Run specific test method**: `./mvnw test -Dtest=CIP30VerifierTest#validSignatureWithAddressAndPublicKey1`
- **Generate test coverage report**: Tests automatically generate JaCoCo coverage reports in `target/site/jacoco/`

### Development
- **Compile only**: `./mvnw compile`
- **Generate Javadoc**: `./mvnw javadoc:javadoc` (output in `target/site/apidocs/`)
- **Create shaded JAR**: `./mvnw package` (creates dependency-reduced-pom.xml and shaded JAR)

## Project Architecture

This is a Java 17+ library that implements CIP-30 Data Signature parsing and validation for Cardano blockchain applications. The library provides cryptographic signature verification using Ed25519 and COSE (CBOR Object Signing and Encryption) standards.

### Core Components

**CIP30Verifier** (`src/main/java/org/cardanofoundation/cip30/CIP30Verifier.java`)
- Main entry point for signature verification
- Accepts hex-encoded CBOR bytes of COSE_Sign1 and optional COSE_Key
- Performs Ed25519 signature verification against COSE payload
- Handles both hardware wallet scenarios (hashed content) and standard scenarios (unhashed content)

**Cip30VerificationResult** (`src/main/java/org/cardanofoundation/cip30/Cip30VerificationResult.java`)
- Contains all extracted information from signature verification
- Provides methods to access address, message, public key, signature, and COSE payload in various formats
- Includes `verifyPayload(String)` helper method for external payload validation:
  - For hashed signatures: hashes payload with Blake2b-224 and compares with message
  - For unhashed signatures: compares payload directly with message

**Supporting Enums**
- `ValidationError`: Defines possible validation failure reasons
- `AddressFormat`: HEX or TEXT (Bech32) address formats
- `MessageFormat`: HEX, TEXT, or BASE64 message formats

### Key Dependencies
- **Cardano Client Libraries**: Provides Blake2b hashing, address utilities, and CIP-8/COSE support
- **Ed25519 Crypto**: Net.i2p EdDSA library for signature verification
- **CBOR Processing**: Co.nstant library for CBOR decoding/encoding

### Signature Types
The library handles two main signature scenarios:

1. **Standard Signatures** (`isHashed() = false`): Message content is stored directly in the signature
2. **Hardware Wallet Signatures** (`isHashed() = true`): Only Blake2b-224 hash of the message is stored, requiring external payload for verification

### Testing Approach
- Comprehensive test suite in `CIP30VerifierTest` covering valid/invalid signatures, address extraction, and payload verification
- Tests include real-world examples from hardware wallets (Ledger) and software wallets
- Separate focused tests for hashed vs unhashed payload verification scenarios
- Use @Nested tests when possible