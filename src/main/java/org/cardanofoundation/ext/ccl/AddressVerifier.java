package org.cardanofoundation.ext.ccl;

import java.util.Optional;

import static org.cardanofoundation.cip30.Hashing.blake2bHash224;

public class AddressVerifier {

    /**
     * Verify the provided address with publicKey
     * Reconstruct the address from public key and then compare it with the provided address
     * @param address address
     * @param publicKey public key bytes
     * @return true or false
     */
    public static boolean verifyAddressAgainstPublicKey(Address address, byte[] publicKey) {
        String prefix = address.getPrefix();
        Address.AddressType addressType = address.getAddressType();
        byte[] addressBytes = address.getBytes();
        byte header = addressBytes[0];

        byte[] newAddressBytes;
        Address newAddress;
        if (Address.AddressType.Reward.equals(addressType)) {
            byte[] stakeKeyHash = blake2bHash224(publicKey); //Get keyhash from publickey (stake credential)
            newAddressBytes = getAddressBytes(null, stakeKeyHash, addressType, header);
        } else {
            byte[] stakeKeyHash = getDelegationCredentialHash(address).orElse(null); //Get stakekeyhash from existing address
            byte[] paymentKeyHash = blake2bHash224(publicKey); //calculate keyhash from public key
            newAddressBytes = getAddressBytes(paymentKeyHash, stakeKeyHash, addressType, header);
        }

        newAddress = new Address(prefix, newAddressBytes);

        return newAddress.toBech32().equals(address.toBech32());
    }

    private static byte[] getAddressBytes(byte[] paymentKeyHash, byte[] stakeKeyHash, Address.AddressType addressType, byte header) {
        byte[] addressArray;
        switch (addressType) {
            case Base, Ptr -> {
                addressArray = new byte[1 + paymentKeyHash.length + stakeKeyHash.length];
                addressArray[0] = header;
                System.arraycopy(paymentKeyHash, 0, addressArray, 1, paymentKeyHash.length);
                System.arraycopy(stakeKeyHash, 0, addressArray, paymentKeyHash.length + 1, stakeKeyHash.length);
            }
            case Enterprise -> {
                addressArray = new byte[1 + paymentKeyHash.length];
                addressArray[0] = header;
                System.arraycopy(paymentKeyHash, 0, addressArray, 1, paymentKeyHash.length);
            }
            case Reward -> {
                addressArray = new byte[1 + stakeKeyHash.length];
                addressArray[0] = header;
                System.arraycopy(stakeKeyHash, 0, addressArray, 1, stakeKeyHash.length);
            }

            default -> throw new RuntimeException("Unknown address type");
        }
        return addressArray;
    }

    public static Optional<byte[]> getDelegationCredentialHash(Address address) {
        Address.AddressType addressType = address.getAddressType();
        byte[] addressBytes = address.getBytes();

        byte[] stakeKeyHash;
        switch (addressType) {
            case Base -> {
                stakeKeyHash = new byte[28];
                System.arraycopy(addressBytes, 1 + 28, stakeKeyHash, 0, stakeKeyHash.length);
            }
            case Enterprise -> stakeKeyHash = null;
            case Reward -> {
                stakeKeyHash = new byte[28];
                System.arraycopy(addressBytes, 1, stakeKeyHash, 0, stakeKeyHash.length);
            }
            case Ptr -> { //TODO -- Remove if not required
                stakeKeyHash = new byte[addressBytes.length - 1 - 28];
                System.arraycopy(addressBytes, 1 + 28, stakeKeyHash, 0, stakeKeyHash.length);
            }
            default -> throw new RuntimeException("DelegationHash can't be found for address type : " + addressType);
        }

        return Optional.ofNullable(stakeKeyHash);
    }

}
