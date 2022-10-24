package org.cardanofoundation.ext.cose;

import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.DataItem;
import org.cardanofoundation.ext.cbor.CborRuntimeException;
import org.cardanofoundation.ext.cbor.MoreCbor;

public interface COSEItem {

    default byte[] serializeAsBytes() {
        var di = serialize();

        try {
            return MoreCbor.serialize(di, false);
        } catch (CborException e) {
            throw new CborRuntimeException("Cbor serializaion error", e);
        }
    }

    DataItem serialize();
}