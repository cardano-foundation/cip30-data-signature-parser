package org.cardanofoundation.cip8;

import java.util.HexFormat;

public final class MoreHex {

    private final static HexFormat HEX_FORMAT = HexFormat.of();

    public static String to(byte[] data) {
        return HEX_FORMAT.formatHex(data);
    }

    public static byte[] from(String hex) {
        return HEX_FORMAT.parseHex(hex);
    }

}
