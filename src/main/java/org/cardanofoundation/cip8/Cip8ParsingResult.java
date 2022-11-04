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

public class Cip8ParsingResult {

    private static final Logger logger = LoggerFactory.getLogger(CIP8Parser.class);

    private Optional<ValidationError> validationError = Optional.empty();

    private Optional<byte[]> address = Optional.empty();
    private byte[] publicKey;
    private byte[] signature;
    private byte[] message;
    private byte[] cosePayload;

    public static class Builder {

        private Optional<ValidationError> validationError = Optional.empty();

        private Optional<byte[]> address = Optional.empty();
        private byte[] publicKey;
        private byte[] signature;
        private byte[] message;
        private byte[] cosePayload;

        static Builder newBuilder() {
            return new Builder();
        }

        public Builder valid() {
            this.validationError = Optional.empty();
            return Builder.this;
        }

        public Builder validationError(ValidationError error) {
            Objects.requireNonNull(error, "validation error is required");

            this.validationError = Optional.of(error);
            return Builder.this;
        }

        public Builder address(byte[] address) {
            Objects.requireNonNull(address, "address is required");
            this.address = Optional.of(address);
            return Builder.this;
        }

        public Builder publicKey(byte[] publicKey) {
            Objects.requireNonNull(publicKey, "public key is required");
            this.publicKey = publicKey;
            return Builder.this;
        }

        public Builder signature(byte[] signature) {
            Objects.requireNonNull(signature, "signature is required");
            this.signature = signature;
            return Builder.this;
        }

        public Builder message(byte[] message) {
            this.message = message;
            return Builder.this;
        }

        public Builder cosePayload(byte[] cosePayload) {
            this.cosePayload = cosePayload;
            return Builder.this;
        }

        public Cip8ParsingResult build() {
            return new Cip8ParsingResult(this);
        }
    }

    private Cip8ParsingResult(Builder builder) {
        this.validationError = builder.validationError;
        this.address = builder.address;
        this.publicKey = builder.publicKey;
        this.signature = builder.signature;
        this.message = builder.message;
        this.cosePayload = builder.cosePayload;
    }

    public boolean isValid() {
        return validationError.isEmpty();
    }

    public Optional<ValidationError> getValidationError() {
        return validationError;
    }

    public Optional<byte[]> getAddress() {
        return address;
    }

    // TODO document
    public @Nullable byte[] getPublicKey() {
        return publicKey;
    }

    public @Nullable byte[] getSignature() {
        return signature;
    }

    public @Nullable byte[] getMessage() {
        return message;
    }

    public @Nullable byte[] getCosePayload() {
        return cosePayload;
    }

    public String getPublicKey(Format f, Charset c) {
        return formatter(publicKey, f, c);
    }

    public @Nullable String getPublicKey(Format f) {
        return getPublicKey(f, UTF_8);
    }

    public @Nullable String getSignature(Format f, Charset c) {
        return formatter(signature, f, c);
    }

    public @Nullable String getSignature(Format f) {
        return getSignature(f, UTF_8);
    }

    public @Nullable String getMessage(Format f, Charset c) {
        return formatter(message, f, c);
    }

    public @Nullable String getMessage(Format f) {
        return getMessage(f, UTF_8);
    }

    public @Nullable String getCosePayload(Format f) {
        return getCosePayload(f, UTF_8);
    }

    public @Nullable String getCosePayload(Format f, Charset c) {
        return formatter(cosePayload, f, c);
    }

    public static Cip8ParsingResult createInvalid(ValidationError error) {
        return Builder.newBuilder()
                .validationError(error)
                .build();
    }

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
