package org.cardanofoundation.cip8;

import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.*;
import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;

import java.security.MessageDigest;
import java.util.Optional;

import static co.nstant.in.cbor.CborDecoder.decode;
import static co.nstant.in.cbor.model.MajorType.ARRAY;
import static co.nstant.in.cbor.model.MajorType.MAP;
import static net.i2p.crypto.eddsa.EdDSAEngine.ONE_SHOT_MODE;
import static net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable.ED_25519;
import static org.cardanofoundation.cip8.MoreHex.from;
import static org.cardanofoundation.ext.cbor.MoreCbor.serialize;
import static org.cardanofoundation.ext.cose.COSEKey.deserialize;

public final class CIP8Parser {

    // simple logging SLF4J

    private static final EdDSAParameterSpec ED_DSA_PARAMETER_SPEC = EdDSANamedCurveTable.getByName(ED_25519);
    private static final long PUBLIC_KEY_INDEX = -2;

    private final String signature;
    private final Optional<String> publicKey;

    public CIP8Parser(String signature, Optional<String> publicKey) {
        if (signature == null) {
            throw new IllegalArgumentException("signature cannot be null");
        }
        this.signature = signature;
        this.publicKey = publicKey;
    }

    public CIP8Parser(String signature) {
        this.signature = signature;
        this.publicKey = Optional.empty();
    }

    public CIP8Parser(String signature, String publicKey) {
        if (signature == null) {
            throw new IllegalArgumentException("signature cannot be null");
        }
        if (signature.isBlank()) {
            throw new IllegalArgumentException("signature cannot blank");
        }
        this.signature = signature;
        this.publicKey = Optional.ofNullable(publicKey);
    }

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

    public Cip8ParsingResult parse() {
        return verifyCIP8Signature(signature, publicKey);
    }

    private static Cip8ParsingResult verifyCIP8Signature(final String signature,
                                                         final Optional<String> publicKey) {
        try {
            var signatureAsBytes = from(signature);

            var coseCbor = decode(signatureAsBytes).get(0);

            if (coseCbor.getMajorType() != ARRAY) {
                //log.warn("invalid CIP-8 signature. Structure is not an array.");
                return Cip8ParsingResult.createInvalid();
            }

            var dataItems = ((Array) coseCbor).getDataItems();
            var protectedHeader = (ByteString) dataItems.get(0); // 1

            var messageByteString = (ByteString) dataItems.get(2); // 3

            var signatureByteString = (ByteString) dataItems.get(3); // 4

            var protectedHeaderDecoded = CborDecoder.decode(protectedHeader.getBytes()).get(0);

            if (protectedHeaderDecoded.getMajorType() != MAP) {
                //log.warn("invalid CIP-8 signature. Protected header structure is not a map.");
                return Cip8ParsingResult.createInvalid();
            }

            var protectedHeaderMap = (Map) protectedHeaderDecoded;

            var signatureArray = new Array();
            signatureArray.add(new UnicodeString("Signature1"));
            signatureArray.add(protectedHeader);
            signatureArray.add(new ByteString(new byte[0]));
            signatureArray.add(messageByteString);

            var publicKeyBytes = deserialisePublicKey(publicKey, protectedHeaderMap);
            var cosePayload = serialize(signatureArray);

            var isVerified = verifyMessage(
                    cosePayload,
                    signatureByteString.getBytes(),
                    publicKeyBytes
            );

            var b = Cip8ParsingResult.Builder.newBuilder();

            b.valid(isVerified);
            deserialiseAddress(protectedHeaderMap).ifPresent(b::address);
            deserialiseSignedMessage(messageByteString).ifPresent(b::message);
            b.publicKey(publicKeyBytes);
            b.signature(signatureByteString.getBytes());
            b.cosePayload(cosePayload);

            return b.build();
        } catch (CborException | ClassCastException e) {
            return Cip8ParsingResult.createInvalid();
        }
   }

    private static byte[] deserialisePublicKey(Optional<String> key, Map protectedHeaderMap) {
        return key.map(k -> deserialize(from(k)).otherHeaderAsBytes(PUBLIC_KEY_INDEX)).orElseGet(() -> {
            var publicKeyBS = (ByteString) protectedHeaderMap.get(new UnsignedInteger(4));

            return publicKeyBS.getBytes();
        });
    }

    private static Optional<byte[]> deserialiseSignedMessage(ByteString messageByteString) {
        return Optional.ofNullable(messageByteString.getBytes());
    }

    private static Optional<byte[]> deserialiseAddress(Map protectedHeaderMap) {
        return Optional.ofNullable((ByteString) protectedHeaderMap.get(new UnicodeString("address")))
                .filter(byteString -> byteString.getBytes().length > 0)
                .map(ByteString::getBytes);
    }

}
