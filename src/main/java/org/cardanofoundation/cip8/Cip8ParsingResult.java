package org.cardanofoundation.cip8;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.nio.charset.Charset;
import java.util.Base64;
import java.util.Objects;
import java.util.Optional;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.cardanofoundation.cip8.MoreHex.to;

/**
 * The Cip8ParsingResult is used to represent the information of a decoded message that uses
 * the CIP 8 specification of the Cardano protocol.
 * For further information on CIP 8, see <A href="https://cips.cardano.org/cips/cip8/">
 * https://cips.cardano.org/cips/cip8/</A>.
 */
public class Cip8ParsingResult {

    /**
     * Static instance of {@code Logger} used for logging.
     */
    private static final Logger logger = LoggerFactory.getLogger(CIP8Parser.class);

    /**
     * Provides information in case that the validation of the message fails.
     */
    private Optional<ValidationError> validationError = Optional.of(ValidationError.UNKNOWN);

    /**
     * Optional array of bytes that contains TODO
     */
    private Optional<byte[]> address = Optional.empty();

    /**
     * Array of bytes that contains the public key used to sign the message using CIP 8.
     */
    private byte[] publicKey;

    /**
     * Array of bytes that contains the signature of the message signed using CIP 8.
     */
    private byte[] signature;

    /**
     * Array of bytes that contains the message contained in the signature signed by the
     * public key.
     */
    private byte[] message;

    /**
     * TODO
     */
    private byte[] cosePayload;

    /**
     * Builder of the class {@code Cip8ParsingResult} that follows the builder design
     * pattern.
     */
    public static class Builder {


        /**
         * Provides information in case that the validation of the message fails.
         */
        private Optional<ValidationError> validationError = Optional.of(ValidationError.UNKNOWN);

        /**
         * Optional array of bytes that contains TODO
         */
        private Optional<byte[]> address = Optional.empty();

        /**
         * Array of bytes that contains the public key used to sign the message using CIP 8.
         */
        private byte[] publicKey;

        /**
         * Array of bytes that contains the signature of the message signed using CIP 8.
         */
        private byte[] signature;

        /**
         * Array of bytes that contains the message contained in the signature signed by the
         * public key.
         */
        private byte[] message;

        /**
         * TODO
         */
        private byte[] cosePayload;

        /**
         * Creates an object {@code Builder} in charge of building the class
         * {@code Cip8ParsingResult}.
         *
         * @return the builder of the class {@code Cip8ParsingResult}.
         */
        static Builder newBuilder() {
            return new Builder();
        }

        /**
         * Sets the field validationError as an empty optional.
         *
         * @return the builder object.
         */
        public Builder valid() {
            this.validationError = Optional.empty();
            return Builder.this;
        }

        /**
         * Provides a validation error of the enum {@code ValidationError}.
         *
         * @param error validation error corresponding with the reason why the
         *              information provided is not valid.
         * @return the builder object.
         */
        public Builder validationError(ValidationError error) {
            Objects.requireNonNull(error, "validation error is required");

            this.validationError = Optional.of(error);
            return Builder.this;
        }

        /**
         * Provides the address of the TODO
         *
         * @param address array of bytes that contains the address of the TODO
         * @return the builder object.
         */
        public Builder address(byte[] address) {
            Objects.requireNonNull(address, "address is required");
            this.address = Optional.of(address);
            return Builder.this;
        }

        /**
         * Provides the public key to decode the message.
         *
         * @param publicKey array of bytes that contains the public key to TODO
         * @return the builder object.
         */
        public Builder publicKey(byte[] publicKey) {
            Objects.requireNonNull(publicKey, "public key is required");
            this.publicKey = publicKey;
            return Builder.this;
        }

        /**
         * Provides the signature of the message.
         *
         * @param signature array of bytes that contains the signature of the message.
         * @return the builder object.
         */
        public Builder signature(byte[] signature) {
            Objects.requireNonNull(signature, "signature is required");
            this.signature = signature;
            return Builder.this;
        }

        /**
         * Provides the message.
         *
         * @param message array of bytes that contains the message.
         * @return the builder object.
         */
        public Builder message(byte[] message) {
            this.message = message;
            return Builder.this;
        }

        /**
         * Provides the cose payload.
         *
         * @param cosePayload array of bytes that contains the cose payload.
         * @return the builder object.
         */
        public Builder cosePayload(byte[] cosePayload) {
            this.cosePayload = cosePayload;
            return Builder.this;
        }

        /**
         * Creates an instance of the class {@code Cip8ParsingResult} using the information
         * stored.
         *
         * @return an instance of the class {@code Cip8ParsingResult} with the information
         * contained by the builder.
         */
        public Cip8ParsingResult build() {
            return new Cip8ParsingResult(this);
        }
    }

    /**
     * Saves the fields collected by the object {@code Builder}.
     *
     * @param builder object in charge of collecting all the information
     *                necessary to build a {@code Cip8ParsingResult} object.
     */
    private Cip8ParsingResult(Builder builder) {
        this.validationError = builder.validationError;
        this.address = builder.address;
        this.publicKey = builder.publicKey;
        this.signature = builder.signature;
        this.message = builder.message;
        this.cosePayload = builder.cosePayload;
    }

    /**
     * Checks if the message provided is valid.
     *
     * @return True if the message is valid, false otherwise.
     */
    public boolean isValid() {
        return validationError.isEmpty();
    }

    /**
     * Returns an optional of the enum {@code ValidationError}.
     *
     * @return if the message is not valid information about the reason, otherwise
     * an empty optional.
     */
    public Optional<ValidationError> getValidationError() {
        return validationError;
    }

    /**
     * Returns TODO
     *
     * @return an optional of an array of bytes containing the address if there is one,
     * otherwise an empty optional.
     */
    public Optional<byte[]> getAddress() {
        return address;
    }

    /**
     * Returns an array of bytes containing the public key to decode the signature.
     *
     * @return an array of bytes containing the public key if there is one, otherwise null.
     */
    public @Nullable byte[] getPublicKey() {
        return publicKey;
    }

    /**
     * Returns an array of bytes containing the signature of the message.
     *
     * @return an array of bytes containing the signature if there is one, otherwise null.
     */
    public @Nullable byte[] getSignature() {
        return signature;
    }

    /**
     * Returns an array of bytes containing a message.
     *
     * @return an array of bytes containing the message if there is one, otherwise null.
     */
    public @Nullable byte[] getMessage() {
        return message;
    }

    /**
     * Returns an array of bytes containing the cose payload.
     *
     * @return an array of bytes containing the cose payload if there is one,
     * otherwise null.
     */
    public @Nullable byte[] getCosePayload() {
        return cosePayload;
    }

    /**
     * Returns the public key in a specific encoding format and charset.
     * <p>
     * The possible encoding formats are defined by the enum {@code Format} and
     * the possible charset by the enum {@code StandardCharsets}.
     *
     * @param f The encoding format wanted for the returned public key.
     * @param c The charset wanted for the returned public key.
     * @return the public key in the provided encoding format and charset.
     */
    public String getPublicKey(Format f, Charset c) {
        return formatter(publicKey, f, c);
    }

    /**
     * Returns the public key in a specific encoding format and {@code UTF_8} charset.
     * <p>
     * The possible encoding formats are defined by the enum {@code Format} and
     * the charset is {@code UTF_8}.
     *
     * @param f The encoding format wanted for the returned public key.
     * @return the public key in the provided encoding format.
     */
    public @Nullable String getPublicKey(Format f) {
        return getPublicKey(f, UTF_8);
    }

    /**
     * Returns the signature of the message in a specific encoding format and charset.
     * <p>
     * The possible encoding formats are defined by the enum {@code Format} and
     * the possible charset by the enum {@code StandardCharsets}.
     *
     * @param f The encoding format wanted for the returned signature.
     * @param c The charset wanted for the returned signature.
     * @return the signature of the message in the provided encoding format and charset.
     */
    public @Nullable String getSignature(Format f, Charset c) {
        return formatter(signature, f, c);
    }

    /**
     * Returns the signature of the message in a specific encoding format and
     * {@code UTF_8} charset.
     * <p>
     * The possible encoding formats are defined by the enum {@code Format} and
     * the charset is {@code UTF_8}.
     *
     * @param f The encoding format wanted for the returned signature.
     * @return the signature of the message in the provided encoding format.
     */
    public @Nullable String getSignature(Format f) {
        return getSignature(f, UTF_8);
    }

    /**
     * Returns the message in a specific encoding format and charset.
     * <p>
     * The possible encoding formats are defined by the enum {@code Format} and
     * the possible charset by the enum {@code StandardCharsets}.
     *
     * @param f The encoding format wanted for the returned message.
     * @param c The charset wanted for the returned message.
     * @return the message in the provided encoding format and charset.
     */
    public @Nullable String getMessage(Format f, Charset c) {
        return formatter(message, f, c);
    }

    /**
     * Returns the message in a specific encoding format and {@code UTF_8} charset.
     * <p>
     * The possible encoding formats are defined by the enum {@code Format} and
     * the charset is {@code UTF_8}.
     *
     * @param f The encoding format wanted for the returned message.
     * @return the message in the provided encoding format.
     */
    public @Nullable String getMessage(Format f) {
        return getMessage(f, UTF_8);
    }

    /**
     * Returns the cose payload in a specific encoding format and {@code UTF_8} charset.
     * <p>
     * The possible encoding formats are defined by the enum {@code Format} and
     * the charset is {@code UTF_8}.
     *
     * @param f The encoding format wanted for the returned cose payload.
     * @return the cose payload in the provided encoding format.
     */
    public @Nullable String getCosePayload(Format f) {
        return getCosePayload(f, UTF_8);
    }

    /**
     * Returns the cose payload in a specific encoding format and charset.
     * <p>
     * The possible encoding formats are defined by the enum {@code Format} and
     * the possible charset by the enum {@code StandardCharsets}.
     *
     * @param f The encoding format wanted for the returned cose payload.
     * @param c The charset wanted for the returned cose payload.
     * @return the cose payload in the provided encoding format and charset.
     */
    public @Nullable String getCosePayload(Format f, Charset c) {
        return formatter(cosePayload, f, c);
    }

    /**
     * Creates a new {@code Cip8ParsingResult} containing information of
     * the validation error in case that the information is not valid with the
     * CIP 8 specification.
     *
     * @param error the value of the enum {@code ValidationError} corresponding with
     *              the reason why the information is not valid.
     * @return a new {@code Cip8ParsingResult} containing information of
     * the validation error.
     */
    public static Cip8ParsingResult createInvalid(ValidationError error) {
        return Builder.newBuilder()
                .validationError(error)
                .build();
    }

    /**
     * Changes the format of the information provided.
     * <p>
     * The possible encoding formats are defined by the enum {@code Format} and
     * the possible charset by the enum {@code StandardCharsets}.
     *
     * @param bytes array of bytes with the information to be formatted.
     * @param f     The encoding format wanted for the returned information.
     * @param c     The charset wanted for the returned information.
     * @return array of bytes provided transformed to the encoding and format and
     * charset specified.
     */
    private String formatter(byte[] bytes, Format f, Charset c) {
        if (bytes == null) {
            return null;
        }
        if (f == null) {
            throw new IllegalArgumentException("format must be defined");
        }
        if (c == null) {
            throw new IllegalArgumentException("charset must be defined");
        }

        return switch (f) {
            case HEX -> to(bytes);
            case TEXT -> new String(bytes, c);
            case BASE64 -> Base64.getEncoder().encodeToString(bytes);
        };
    }

    /**
     * Returns a string representation of this {@code Cip8ParsingResult}. This method is
     * intended to be used only for debugging purposes.
     *
     * @return a string representation of this {@code Cip8ParsingResult}.
     */
    @Override
    public String toString() {
        return "Cip8ParsingResult{" +
                "valid=" + validationError.isEmpty() +
                ", validationError=" + validationError +
                ", address=" + address +
                ", publicKey=" + publicKey +
                ", signature=" + signature +
                ", message=" + message +
                ", cosePayload=" + cosePayload +
                '}';
    }

}
