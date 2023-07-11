package org.cardanofoundation.cip30;

import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.*;
import com.bloxbean.cardano.client.address.Address;
import com.bloxbean.cardano.client.cip.cip8.COSEKey;
import com.bloxbean.cardano.client.util.HexUtil;
import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.annotation.ParametersAreNonnullByDefault;
import java.security.MessageDigest;
import java.util.Objects;
import java.util.Optional;

import static co.nstant.in.cbor.CborDecoder.decode;
import static co.nstant.in.cbor.model.MajorType.ARRAY;
import static co.nstant.in.cbor.model.MajorType.MAP;
import static com.bloxbean.cardano.client.address.AddressProvider.verifyAddress;
import static com.bloxbean.cardano.client.common.cbor.CborSerializationUtil.serialize;
import static net.i2p.crypto.eddsa.EdDSAEngine.ONE_SHOT_MODE;
import static net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable.ED_25519;
import static org.cardanofoundation.cip30.ValidationError.CIP8_FORMAT_ERROR;
import static org.cardanofoundation.cip30.ValidationError.NO_PUBLIC_KEY;

/**
 * The {@code CIP30Verifier} class is used to verify and parse Data Signature part of the Cardano protocol.
 *
 * Please refer to GLOSSARY.md for definition of the terms and CIP 30 (signData), see: <a href="https://cips.cardano.org/cips/cip30/">
 * https://cips.cardano.org/cips/cip30/</a>.
 */
@ParametersAreNonnullByDefault
public final class CIP30Verifier {

    /**
     * Static instance of {@code Logger} used for logging.
     */
    private static final Logger logger = LoggerFactory.getLogger(CIP30Verifier.class);

    private static final EdDSAParameterSpec ED_DSA_PARAMETER_SPEC = EdDSANamedCurveTable.getByName(ED_25519);

    /**
     * hex-encoded CBOR bytes of the COSE_Sign1
     */
    private final String coseSign1;

    /**
     * Optional hex-encoded CBOR bytes of the COSE_Key.
     * Hint: not all wallets and implementations will put public key in COSE_Sign1, such a key can be explicitly passed.
     */
    private final Optional<String> coseKey;

    /**
     * Creates an {@code CIP30Verifier}.
     *
     * @param coseSign1 - hex-encoded CBOR bytes of the COSE_Sign1
     */
    public CIP30Verifier(String coseSign1) {
        this(coseSign1, Optional.empty());
    }

    /**
     * Creates an {@code CIP30Verifier}.
     *
     * @param coseSign1 - hex-encoded CBOR bytes of the COSE_Sign1.
     * @param coseKey - Optional hex-encoded CBOR bytes of the COSE_Key
     */
    public CIP30Verifier(String coseSign1, @Nullable String coseKey) {
        this(coseSign1, Optional.ofNullable(coseKey));
    }

    /**
     * Creates an {@code CIP30Verifier}.
     *
     * @param coseSign1 - hex-encoded CBOR bytes of the COSE_Sign1P 8.
     * @param coseKey - Optional hex-encoded CBOR bytes of the COSE_Key
     */
    public CIP30Verifier(String coseSign1, Optional<String> coseKey) {
        Objects.requireNonNull(coseSign1, "signature cannot be null");
        if (coseSign1.isBlank()) {
            throw new IllegalArgumentException("signature cannot blank");
        }
        this.coseSign1 = coseSign1;
        this.coseKey = coseKey;
    }

    /**
     * In order to check validity of ED 25519 signature we have to verify COSE1 payload using ED 25519 public key
     *
     * @param cosePayload    - COSE Payload to verify
     * @param signatureBytes - signed ED 25519 signature - extracted from CIP-30 DataSignature ('signature' field)
     * @param publicKeyBytes - ED 25519 public key - either extracted from CIP-30 DataSignature ('key' field) or explicitly passed in
     *
     * @return true if supplied signature is valid according to the supplied ED 25519 public key
     */
    private static boolean verifyMessage(final byte[] cosePayload,
                                         final byte[] signatureBytes,
                                         final byte[] publicKeyBytes) {
        try {
            var publicKey = new EdDSAPublicKey(new EdDSAPublicKeySpec(publicKeyBytes, ED_DSA_PARAMETER_SPEC));
            var signature = new EdDSAEngine(MessageDigest.getInstance(ED_DSA_PARAMETER_SPEC.getHashAlgorithm()));
            signature.initVerify(publicKey);
            signature.setParameter(ONE_SHOT_MODE);
            signature.update(cosePayload);

            return signature.verify(signatureBytes);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Parses and verifies the DataSignature part of CIP-30 (signature and key).
     *
     * @return an instance of {@code Cip30VerificationResult}
     * that contains all the information of the parsing / verification process
     */
    public Cip30VerificationResult verify() {
        try {
            var signatureAsBytes = HexUtil.decodeHexString(coseSign1);

            var coseCbor = decode(signatureAsBytes).get(0);

            if (coseCbor.getMajorType() != ARRAY) {
                logger.error("Invalid CIP-30 signature. Structure is not an array.");
                return Cip30VerificationResult.createInvalid(CIP8_FORMAT_ERROR);
            }

            var dataItems = ((Array) coseCbor).getDataItems();
            var protectedHeader = (ByteString) dataItems.get(0); // 1

            var messageByteString = (ByteString) dataItems.get(2); // 3

            var ed25519SignatureByteString = (ByteString) dataItems.get(3); // 4

            var protectedHeaderDecoded = CborDecoder.decode(protectedHeader.getBytes()).get(0);

            if (protectedHeaderDecoded.getMajorType() != MAP) {
                logger.error("Invalid CIP-30 signature. Protected header structure is not a map.");
                return Cip30VerificationResult.createInvalid(CIP8_FORMAT_ERROR);
            }

            var protectedHeaderMap = (Map) protectedHeaderDecoded;

            var signatureArray = new Array();
            signatureArray.add(new UnicodeString("Signature1"));
            signatureArray.add(protectedHeader);
            signatureArray.add(new ByteString(new byte[0]));
            signatureArray.add(messageByteString);

            var ed25519PublicKeyBytes = deserializeED25519PublicKey(coseKey, protectedHeaderMap);
            if (ed25519PublicKeyBytes == null) {
                logger.error("No public key found.");
                return Cip30VerificationResult.createInvalid(NO_PUBLIC_KEY);
            }

            var cosePayload = serialize(signatureArray);

            var isSignatureVerified = verifyMessage(
                    cosePayload,
                    ed25519SignatureByteString.getBytes(),
                    ed25519PublicKeyBytes
            );

            var maybeAddress = Optional.ofNullable(getED25519PublicKeyFromProtectedHeaders(protectedHeaderMap)).map(Address::new);
            var maybePubKey = Optional.ofNullable(getED25519PublicKeyFromCoseKey(coseKey));

            var isAddressVerified = true;
            if (maybeAddress.isPresent() && maybePubKey.isPresent()) {
                isAddressVerified = verifyAddress(maybeAddress.orElseThrow(), maybePubKey.orElseThrow());
            }

            var b = Cip30VerificationResult.Builder.newBuilder();

            if (isSignatureVerified && isAddressVerified) {
                b.valid();
            }

            deserializeAddressFromHeaderMap(protectedHeaderMap).ifPresent(b::address);
            Optional.ofNullable(messageByteString.getBytes()).map(b::message);
            b.ed25519PublicKey(ed25519PublicKeyBytes);
            b.ed25519Signature(ed25519SignatureByteString.getBytes());
            b.cosePayload(cosePayload);

            return b.build();
        } catch (CborException | ClassCastException e) {
            return Cip30VerificationResult.createInvalid(CIP8_FORMAT_ERROR);
        }
    }

    /**
     * Returns hex CBOR encoded COSE_Sign1
     *
     * @return COSE_Sign1
     */
    public String getCOSESign1() {
        return coseSign1;
    }

    /**
     * Returns an optional of string containing the public key used to sign the message.
     *
     * @return the public key used to sign the message using CIP 30.
     */
    public Optional<String> getCoseKey() {
        return coseKey;
    }

    /**
     * Deserializes ED 25519 public key from supplied COSE_Key.
     * <p>
     * Function will first check if ED 25519 public key is available in the COSE_Key header section (-2 index),
     * if not it will extract public key from protectedHeaderMap taken from COSE_Sig1 (4 index).
     *
     * @param coseKey - actual COSE_Key from DataSignature field of CIP-30 signData function
     * @param protectedHeaderMap - extracted protected header map from COSE_Sig1
     * @return an array of bytes containing ED 25519 public key or null if neither supplied COSE_Key and protectedHeaderMap
     * contains ED 25519 public key
     */
    private static @Nullable byte[] deserializeED25519PublicKey(Optional<String> coseKey, Map protectedHeaderMap) {
        return coseKey.map(hexString -> COSEKey.deserialize(HexUtil.decodeHexString(hexString)).otherHeaderAsBytes(-2))
                .orElseGet(() -> getED25519PublicKeyFromProtectedHeaders(protectedHeaderMap));
    }

    /**
     * Deserialise ED 25519 public key from protected header map.
     * @param protectedHeaderMap
     * @return ED 25519 public key
     */
    private static @Nullable byte[] getED25519PublicKeyFromProtectedHeaders(Map protectedHeaderMap) {
        var publicKeyBS = (ByteString) protectedHeaderMap.get(new UnsignedInteger(4));
        if (publicKeyBS == null) {
            return null;
        }

        return publicKeyBS.getBytes();
    }

    /**
     * Deserialise ED 25519 public key from COSE_Key.
     *
     * @param coseKey
     * @return
     */
    private static byte[] getED25519PublicKeyFromCoseKey(Optional<String> coseKey) {
        return coseKey.map(hexString -> COSEKey.deserialize(HexUtil.decodeHexString(hexString)).otherHeaderAsBytes(-2)).orElse(null);
    }

    /**
     * Extracts Cardano address.
     *
     * @param protectedHeaderMap - protectedHeaderMap stored in signature field of DataSignature.
     * @return an optional array of bytes containing the deserialized address if there is one,
     * otherwise an empty optional.
     */
    private static Optional<byte[]> deserializeAddressFromHeaderMap(Map protectedHeaderMap) {
        return Optional.ofNullable((ByteString) protectedHeaderMap.get(new UnicodeString("address")))
                .filter(byteString -> byteString.getBytes().length > 0)
                .map(ByteString::getBytes);
    }

}
