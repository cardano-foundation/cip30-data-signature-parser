package org.cardanofoundation.ext.ccl;

import org.cardanofoundation.ext.bech32.Bech32;

/**
 * Address class represents Shelley address
 */
public class Address {

    private String prefix;
    private final byte[] bytes;
    private String address;
    private final AddressType addressType;

    /**
     * Create Address from a byte array
     * @param prefix Address prefix
     * @param bytes Address bytes
     */
    public Address(String prefix, byte[] bytes) {
        this.prefix = prefix;
        this.bytes = bytes;

        this.addressType = readAddressType(this.bytes);
    }

    /**
     * Create Address from a Bech32 address
     * @param address Bech32 address
     */
    public Address(String address) {
        if (address == null || address.isEmpty())
            throw new RuntimeException("Address cannot be null or empty");

        this.address = address;
        Bech32.Bech32Data bech32Data = Bech32.decode(address);
        this.bytes = bech32Data.data;
        this.prefix = bech32Data.hrp;

        this.addressType = readAddressType(this.bytes);
    }

    /**
     * Create Address from a byte array
     * @param addressBytes
     */
    public Address(byte[] addressBytes) {
        if (addressBytes == null)
            throw new RuntimeException("Address cannot be null or empty");

        this.bytes = addressBytes;
        this.addressType = readAddressType(this.bytes);
    }

    public byte[] getBytes() {
        return bytes;
    }

    /**
     * Returns Bech32 encoded address
     * @return Bech32 encoded address
     */
    public String toBech32() {
        if (address == null || address.isEmpty()) {
            address = Bech32.encode(bytes, prefix);
        }
        return address;
    }

    /**
     * Returns address prefix
     * @return address prefix
     */
    public String getPrefix() {
        return prefix;
    }

    /**
     * Returns Bech32 encoded address
     * @return Bech32 encoded address
     */
    public String getAddress() {
        return toBech32();
    }

    /**
     * Returns AddressType
     * @return AddressType
     */
    public AddressType getAddressType() {
        return addressType;
    }

    public static AddressType readAddressType(byte[] addressBytes) {
        byte header = addressBytes[0];

        return switch ((header & 0xF0) >> 4) {
            case 0b0000, 0b0001, 0b0010, 0b0011 -> AddressType.Base; //pointer
            case 0b0100, 0b0101 -> AddressType.Ptr; //enterprise
            case 0b0110, 0b0111 -> AddressType.Enterprise; //reward
            case 0b1110, 0b1111 -> AddressType.Reward;
            case 0b1000 -> AddressType.Byron;
            default -> throw new RuntimeException("Unknown address type");
        };
    }

    public enum AddressType {
        Base,
        Ptr,
        Enterprise,
        Reward,
        Byron
    }

}