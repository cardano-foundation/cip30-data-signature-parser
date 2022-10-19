package org.cardanofoundation.ext.cose;

import co.nstant.in.cbor.model.*;
import org.cardanofoundation.ext.cbor.CborRuntimeException;

import java.math.BigInteger;

class COSEUtil {

    /**
     * Convert a long / Integer / BigInteger / String / byte[] to DataItem
     *
     * @param value
     * @return DataItem
     */
    public static DataItem getDataItemFromObject(Object value) {
        if (value instanceof Long) {
            if (((Long) value).longValue() >= 0)
                return new UnsignedInteger((Long) value);
            else
                return new NegativeInteger((Long) value);
        } else if (value instanceof Integer) {
            if (((Integer) value).intValue() >= 0)
                return new UnsignedInteger((Integer) value);
            else
                return new NegativeInteger((Integer) value);
        } else if (value instanceof BigInteger) {
            BigInteger valueBI = (BigInteger) value;
            if (valueBI.compareTo(BigInteger.ZERO) == 0 || valueBI.compareTo(BigInteger.ZERO) == 1)
                return new UnsignedInteger(valueBI);
            else
                return new NegativeInteger(valueBI);
        } else if (value instanceof String) {
            return new UnicodeString((String) value);
        } else if (value instanceof byte[]) {
            return new ByteString((byte[]) value);
        } else {
            throw new CborRuntimeException(String.format("Serialization error. Expected type: long / Integer / BigInteger / String / byte[], found: %s", value.getClass()));
        }
    }

    /**
     * Convert a DataItem to long or String or byte[]
     *
     * @param dataItem
     * @return long or String value
     */
    public static Object decodeNumberOrTextOrBytesTypeFromDataItem(DataItem dataItem) {
        if (dataItem == null)
            return null;

        if (MajorType.UNSIGNED_INTEGER.equals(dataItem.getMajorType())) {
            return ((UnsignedInteger) dataItem).getValue().longValue();
        } else if (MajorType.NEGATIVE_INTEGER.equals(dataItem.getMajorType())) {
            return ((NegativeInteger) dataItem).getValue().longValue();
        } else if (MajorType.UNICODE_STRING.equals(dataItem.getMajorType())) {
            return ((UnicodeString) dataItem).getString();
        } else if (MajorType.BYTE_STRING.equals(dataItem.getMajorType())) {
            return ((ByteString) dataItem).getBytes();
        } else
            throw new CborRuntimeException(String.format("De-serialization error: Unexpected data type: " + dataItem.getMajorType()));
    }
}