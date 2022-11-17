package org.cardanofoundation.cip30;

import java.util.HexFormat;

/**
 * Class {@code MoreHex} provide some methods to transform data in hexadecimal format
 * or vice versa.
 */
public final class MoreHex {

    /**
     * Static instance of {@code HexFormat} that MoreHex uses.
     */
    private final static HexFormat HEX_FORMAT = HexFormat.of();

    /**
     * Returns a hexadecimal string formatted from a byte array.
     *
     * @param data a non-null array of bytes
     * @return a string hexadecimal formatting of the byte array
     */
    public static String to(byte[] data) {
        return HEX_FORMAT.formatHex(data);
    }

    /**
     * Returns a byte array containing hexadecimal values parsed from the string.
     *
     * @param hex a string containing the byte values with prefix, hexadecimal digits,
     *            suffix, and delimiters
     * @return a byte array with the values parsed from the string
     */
    public static byte[] from(String hex) {
        return HEX_FORMAT.parseHex(hex);
    }

}
