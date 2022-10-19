package org.cardanofoundation.ext.cbor;

public class CborRuntimeException extends RuntimeException {

    public CborRuntimeException(String message) {
        super(message);
    }

    public CborRuntimeException(String message, Throwable cause) {
        super(message, cause);
    }

}
