package org.cardanofoundation.cip8;

import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.*;
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
import static net.i2p.crypto.eddsa.EdDSAEngine.ONE_SHOT_MODE;
import static net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable.ED_25519;
import static org.cardanofoundation.cip8.MoreHex.from;
import static org.cardanofoundation.cip8.ValidationError.CIP8_FORMAT_ERROR;
import static org.cardanofoundation.cip8.ValidationError.NO_PUBLIC_KEY;
import static org.cardanofoundation.ext.cbor.MoreCbor.serialize;
import static org.cardanofoundation.ext.cose.COSEKey.deserialize;

/**
 * The {@code CIP8Parser} class is used to verify and parse a message that uses the CIP 8
 * specification of the Cardano protocol.
 * For further information on CIP 8, see <A href="https://cips.cardano.org/cips/cip8/">
 * https://cips.cardano.org/cips/cip8/</A>.
 */
public final class CIP8Parser {

    /**
     * Static instance of {@code Logger} used for logging.
     */
    private static final Logger logger = LoggerFactory.getLogger(CIP8Parser.class);

    /**
     * TODO
     */
    private static final EdDSAParameterSpec ED_DSA_PARAMETER_SPEC = EdDSANamedCurveTable.getByName(ED_25519);

    /**
     * TODO
     */
    private static final long PUBLIC_KEY_INDEX = -2;

    /**
     * Signature of the message signed using CIP 8.
     */
    private final String signature;

    /**
     * Public key used to sign the message using CIP 8.
     */
    private final Optional<String> publicKey;

    /**
     * Creates an {@code CIP8Parser}.
     *
     * @param signature a string that contains the signature of the message signed using CIP 8.
     */
    @ParametersAreNonnullByDefault
    public CIP8Parser(String signature) {
        this(signature, Optional.empty());
    }

    /**
     * Creates an {@code CIP8Parser}.
     *
     * @param signature a string that contains the signature of the message signed using CIP 8.
     * @param publicKey a string that contains the public key used to sign the message using CIP 8.
     */
    public CIP8Parser(String signature, @Nullable String publicKey) {
        this(signature, Optional.ofNullable(publicKey));
    }

    /**
     * Creates an {@code CIP8Parser}.
     *
     * @param signature a string that contains the signature of the message signed using CIP 8.
     * @param publicKey a string that contains the public key used to sign the message using CIP 8.
     */
    @ParametersAreNonnullByDefault
    public CIP8Parser(String signature, Optional<String> publicKey) {
        Objects.requireNonNull(signature, "signature cannot be null");
        if (signature.isBlank()) {
            throw new IllegalArgumentException("signature cannot blank");
        }
        this.signature = signature;
        this.publicKey = publicKey;
    }

    /**
     * Verifies TODO
     *
     * @param message        an array of bytes that contains the message.
     * @param signatureBytes an array of bytes that contains the signature of the message.
     * @param publicKeyBytes an array of bytes that contains the public key to decode the
     *                       message.
     * @return True if the message can ve verified, False otherwise.
     */
    private static boolean verifyMessage(final byte[] message,
                                         final byte[] signatureBytes,
                                         final byte[] publicKeyBytes) {
        try {
            var publicKey = new EdDSAPublicKey(new EdDSAPublicKeySpec(publicKeyBytes, ED_DSA_PARAMETER_SPEC));
            var signature = new EdDSAEngine(MessageDigest.getInstance(ED_DSA_PARAMETER_SPEC.getHashAlgorithm()));
            signature.initVerify(publicKey);
            signature.setParameter(ONE_SHOT_MODE);
            signature.update(message);

            return signature.verify(signatureBytes);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Parses the signature of the message using the provided public key.
     * an instance of {@code Cip8ParsingResult} that contains all the information
     * of the decoded message.
     */
    public Cip8ParsingResult parse() {
        return verifyCIP8Signature(signature, publicKey);
    }

    /**
     * Returns a string containing the signature of the message signed using CIP 8.
     *
     * @return the signature of the message signed using CIP 8.
     */
    public String getSignature() {
        return signature;
    }

    /**
     * Returns an optional of string containing the public key used to sign the message.
     *
     * @return the public key used to sign the message using CIP 8.
     */
    public Optional<String> getPublicKey() {
        return publicKey;
    }

    /**
     * Verifies that a signature signed with CIP 8 is valid.
     *
     * @param signature the signature of the message signed using CIP 8.
     * @param publicKey the public key used to sign the message using CIP 8.
     * @return an instance of {@code Cip8ParsingResult} that contains all the information
     * of the decoded message.
     */
    private static Cip8ParsingResult verifyCIP8Signature(final String signature,
                                                         final Optional<String> publicKey) {
        try {
            var signatureAsBytes = from(signature);

            var coseCbor = decode(signatureAsBytes).get(0);

            if (coseCbor.getMajorType() != ARRAY) {
                logger.error("Invalid CIP-8 signature. Structure is not an array.");
                return Cip8ParsingResult.createInvalid(CIP8_FORMAT_ERROR);
            }

            var dataItems = ((Array) coseCbor).getDataItems();
            var protectedHeader = (ByteString) dataItems.get(0); // 1

            var messageByteString = (ByteString) dataItems.get(2); // 3

            var signatureByteString = (ByteString) dataItems.get(3); // 4

            var protectedHeaderDecoded = CborDecoder.decode(protectedHeader.getBytes()).get(0);

            if (protectedHeaderDecoded.getMajorType() != MAP) {
                logger.error("Invalid CIP-8 signature. Protected header structure is not a map.");
                return Cip8ParsingResult.createInvalid(CIP8_FORMAT_ERROR);
            }

            var protectedHeaderMap = (Map) protectedHeaderDecoded;

            var signatureArray = new Array();
            signatureArray.add(new UnicodeString("Signature1"));
            signatureArray.add(protectedHeader);
            signatureArray.add(new ByteString(new byte[0]));
            signatureArray.add(messageByteString);

            var publicKeyBytes = deserializePublicKey(publicKey, protectedHeaderMap);
            if (publicKeyBytes == null) {
                logger.error("No public key found.");
                return Cip8ParsingResult.createInvalid(NO_PUBLIC_KEY);
            }

            var cosePayload = serialize(signatureArray);

            var isVerified = verifyMessage(
                    cosePayload,
                    signatureByteString.getBytes(),
                    publicKeyBytes
            );

            var b = Cip8ParsingResult.Builder.newBuilder();

            if (isVerified) {
                b.valid();
            }

            deserializeAddress(protectedHeaderMap).ifPresent(b::address);
            deserializeSignedMessage(messageByteString).ifPresent(b::message);
            b.publicKey(publicKeyBytes);
            b.signature(signatureByteString.getBytes());
            b.cosePayload(cosePayload);

            return b.build();
        } catch (CborException | ClassCastException e) {
            return Cip8ParsingResult.createInvalid(CIP8_FORMAT_ERROR);
        }
    }

    /**
     * Deserializes a public key.
     *
     * @param publicKey          Public key to be deserialized.
     * @param protectedHeaderMap TODO
     * @return an array of bytes containing the deserialized public key if possible,
     * otherwise null.
     */
    private static @Nullable byte[] deserializePublicKey(Optional<String> publicKey, Map protectedHeaderMap) {
        return publicKey.map(k -> deserialize(from(k)).otherHeaderAsBytes(PUBLIC_KEY_INDEX)).orElseGet(() -> {
            var publicKeyBS = (ByteString) protectedHeaderMap.get(new UnsignedInteger(4));
            if (publicKeyBS == null) {
                return null;
            }

            return publicKeyBS.getBytes();
        });
    }

    /**
     * Deserializes a signed message.
     *
     * @param messageByteString the message to be deserialized.
     * @return an optional array of bytes containing the deserialized signed message if
     * there is one, otherwise an empty optional.
     */
    private static Optional<byte[]> deserializeSignedMessage(ByteString messageByteString) {
        return Optional.ofNullable(messageByteString.getBytes());
    }

    /**
     * Deserializes an TODO
     *
     * @param protectedHeaderMap TODO
     * @return an optional array of bytes containing the deserialized address if there is one,
     * otherwise an empty optional.
     */
    private static Optional<byte[]> deserializeAddress(Map protectedHeaderMap) {
        return Optional.ofNullable((ByteString) protectedHeaderMap.get(new UnicodeString("address")))
                .filter(byteString -> byteString.getBytes().length > 0)
                .map(ByteString::getBytes);
    }

}
