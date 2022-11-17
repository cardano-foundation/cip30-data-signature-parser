package org.cardanofoundation.cip8;

/**
 * {@code ValidationError} is an enum representing different errors that can occur
 * during the process of validation of a CIP 8 signature.
 */
public enum ValidationError {
    /**
     * The instance when the reason why the signature is invalid is unknown.
     */
    UNKNOWN,

    /**
     * The instance when the signature do not comply with the CIP 8 specification format.
     */
    CIP8_FORMAT_ERROR, // ???

    /**
     * The instance when the signature do not contain a public key.
     */
    NO_PUBLIC_KEY

}
