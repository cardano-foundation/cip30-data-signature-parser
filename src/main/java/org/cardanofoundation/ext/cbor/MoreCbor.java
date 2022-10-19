package org.cardanofoundation.ext.cbor;

import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.DataItem;

import java.io.ByteArrayOutputStream;

import static java.util.Arrays.stream;

public final class MoreCbor {

    public static byte[] serialize(DataItem value) throws CborException {
        return serialize(new DataItem[] { value }, true); //By default Canonical = true
    }

    public static byte[] serialize(DataItem[] values) throws CborException {
        return serialize(values, true); //By default Canonical = true
    }
    public static byte[] serialize(DataItem value, boolean canonical) throws CborException {
        return serialize(new DataItem[]{ value }, canonical);
    }

    public static byte[] serialize(DataItem[] values, boolean canonical) throws CborException {
        var baos = new ByteArrayOutputStream();

        var cborBuilder = new CborBuilder();

        stream(values).forEach(cborBuilder::add);

        var dataItems = cborBuilder.build();

        if (canonical) {
            new CustomCborEncoder(baos).encode(dataItems);
        } else {
            new CustomCborEncoder(baos).nonCanonical().encode(dataItems);
        }

        return baos.toByteArray();

    }

}
