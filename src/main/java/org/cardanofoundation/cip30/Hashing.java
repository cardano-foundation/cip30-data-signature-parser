package org.cardanofoundation.cip30;

import org.bouncycastle.crypto.digests.Blake2bDigest;

public final class Hashing {

    public static byte[] blake2bHash224(byte[] in) {
        final Blake2bDigest hash = new Blake2bDigest(null, 28, null, null);
        hash.update(in, 0, in.length);
        final byte[] out = new byte[hash.getDigestSize()];
        hash.doFinal(out, 0);

        return out;
    }

}
