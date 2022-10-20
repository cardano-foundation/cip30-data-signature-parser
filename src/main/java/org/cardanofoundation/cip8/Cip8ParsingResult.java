package org.cardanofoundation.cip8;

import java.nio.charset.Charset;
import java.util.Base64;
import java.util.Optional;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.cardanofoundation.cip8.MoreHex.to;

public class Cip8ParsingResult {

    private boolean valid = false;

    private Optional<byte[]> address = Optional.empty();
    private Optional<byte[]> publicKey = Optional.empty();
    private Optional<byte[]> signature = Optional.empty();
    private Optional<byte[]> message = Optional.empty();
    private Optional<byte[]> cosePayload = Optional.empty();

    public static class Builder {

        private boolean valid;
        private Optional<byte[]> address = Optional.empty();
        private Optional<byte[]> publicKey = Optional.empty();
        private Optional<byte[]> signature = Optional.empty();
        private Optional<byte[]> message = Optional.empty();
        private Optional<byte[]> cosePayload = Optional.empty();

        static Builder newBuilder() {
            return new Builder();
        }

        public Builder valid(boolean valid){
            this.valid = valid;
            return Builder.this;
        }

        public Builder address(byte[] address){
            this.address = Optional.of(address);
            return Builder.this;
        }

        public Builder publicKey(byte[] publicKey){
            this.publicKey = Optional.of(publicKey);
            return Builder.this;
        }

        public Builder signature(byte[] signature){
            this.signature = Optional.of(signature);
            return Builder.this;
        }

        public Builder message(byte[] message){
            this.message = Optional.of(message);
            return Builder.this;
        }

        public Builder cosePayload(byte[] cosePayload){
            this.cosePayload = Optional.of(cosePayload);
            return Builder.this;
        }

        public Cip8ParsingResult build() {
            return new Cip8ParsingResult(this);
        }
    }

    private Cip8ParsingResult(Builder builder) {
        this.valid = builder.valid;
        this.address = builder.address;
        this.publicKey = builder.publicKey;
        this.signature = builder.signature;
        this.message = builder.message;
        this.cosePayload = builder.cosePayload;
    }

    public boolean isValid() {
        return valid;
    }

    public Optional<byte[]> getAddress() {
        return address;
    }

    public Optional<byte[]> getPublicKey() {
        return publicKey;
    }

    public Optional<byte[]> getSignature() {
        return signature;
    }

    public Optional<byte[]> getMessage() {
        return message;
    }

    public Optional<byte[]> getCosePayload() {
        return cosePayload;
    }

    public Optional<String> getAddress(Format f, Charset c) {
        return formatter(publicKey, f, c);
    }

    public Optional<String> getAddress(Format f) {
        return getAddress(f, UTF_8);
    }

    public Optional<String> getPublicKey(Format f, Charset c) {
        return formatter(publicKey, f, c);
    }

    public Optional<String> getPublicKey(Format f) {
        return getPublicKey(f, UTF_8);
    }

    public Optional<String> getSignature(Format f, Charset c) {
        return formatter(signature, f, c);
    }

    public Optional<String> getSignature(Format f) {
        return getSignature(f, UTF_8);
    }

    public Optional<String> getMessage(Format f, Charset c) {
        return formatter(message, f, c);
    }

    public Optional<String> getMessage(Format f) {
        return getMessage(f, UTF_8);
    }

    public Optional<String> getCosePayload(Format f) {
        return getCosePayload(f, UTF_8);
    }

    public Optional<String> getCosePayload(Format f, Charset c) {
        return formatter(cosePayload, f, c);
    }

    public static Cip8ParsingResult createInvalid() {
        return Cip8ParsingResult.Builder.newBuilder()
                .valid(false)
                .build();
    }

    private Optional<String> formatter(Optional<byte[]> data, Format f, Charset c) {
        return data.map(bytes -> {
            if (f == Format.HEX) {
                return to(bytes);
            }
            if (f == Format.TEXT) {
                return new String(bytes, c);
            }
            if (f == Format.BASE64) {
                return Base64.getEncoder().encodeToString(bytes);
            }

            throw new RuntimeException("invalid format");
        });
    }

    @Override
    public String toString() {
        return "Cip8ParsingResult{" +
                "valid=" + valid +
                ", address=" + address +
                ", publicKey=" + publicKey +
                ", signature=" + signature +
                ", message=" + message +
                ", cosePayload=" + cosePayload +
                '}';
    }

}
