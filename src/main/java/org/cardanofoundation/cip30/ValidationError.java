package org.cardanofoundation.cip30;

/**
 * {@code ValidationError} is an enum representing different errors that can occur
 * during the process of validation of a CIP-30 DataSignature returned by signData function.
 */
public enum ValidationError {

    /**
     * The instance when the reason why the signature is invalid is unknown.
     */
    UNKNOWN,

    /**
     * The instance when the signature do not comply with the CIP 30 specification format.
     */
    CIP8_FORMAT_ERROR,

    /**
     * The instance when the signature do not contain a public key.
     */
    NO_PUBLIC_KEY

}
