package org.cardanofoundation.cip30;

import org.junit.jupiter.api.Test;

import static com.bloxbean.cardano.client.util.HexUtil.decodeHexString;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.cardanofoundation.cip30.MessageFormat.BASE64;
import static org.cardanofoundation.cip30.MessageFormat.HEX;
import static org.cardanofoundation.cip30.ValidationError.NO_PUBLIC_KEY;
import static org.junit.jupiter.api.Assertions.*;

class CIP30VerifierTest {

    @Test
    void validSignatureWithAddressAndPublicKey() {
        var sig = "84582aa201276761646472657373581de1b83abf370a14870fdfd6ccb35f8b3e62a68e465ed1e096c5a6f5b9d6a166686173686564f4565468697320697320612074657374206d657373616765584042e2bfc4e1929769a0501b884f66794ae3485860f42c01b70fac37f75e40af074c6b2a61b04c6cf8a493c0dced1455b4f1129dbf653ad9801c52ce49ff6d5a0e";
        var key = "a40101032720062158202f1867873147cf53c442435723c17e83beeb8e2153851cd73ccfb1b5e68994a4";

        var p = new CIP30Verifier(sig, key);

        var result = p.verify();

        assertTrue(result.isValid());

        assertTrue(result.getAddress().isPresent(), "Optional address is included in the signature...");

        assertArrayEquals(decodeHexString("e1b83abf370a14870fdfd6ccb35f8b3e62a68e465ed1e096c5a6f5b9d6"), result.getAddress().orElseThrow());
        assertEquals(sig, p.getCOSESign1());
        assertEquals(key, p.getCoseKey().orElseThrow());

        assertArrayEquals(decodeHexString("2f1867873147cf53c442435723c17e83beeb8e2153851cd73ccfb1b5e68994a4"), result.getEd25519PublicKey());
        assertArrayEquals(decodeHexString("42e2bfc4e1929769a0501b884f66794ae3485860f42c01b70fac37f75e40af074c6b2a61b04c6cf8a493c0dced1455b4f1129dbf653ad9801c52ce49ff6d5a0e"), result.getEd25519Signature());
        assertArrayEquals(decodeHexString("846a5369676e617475726531582aa201276761646472657373581de1b83abf370a14870fdfd6ccb35f8b3e62a68e465ed1e096c5a6f5b9d640565468697320697320612074657374206d657373616765"), result.getCosePayload());

        assertEquals("stake1uxur40ehpg2gwr7l6mxtxhut8e32drjxtmg7p9k95m6mn4s0tdy6k", result.getAddress(AddressFormat.TEXT).orElseThrow());

        assertEquals("846a5369676e617475726531582aa201276761646472657373581de1b83abf370a14870fdfd6ccb35f8b3e62a68e465ed1e096c5a6f5b9d640565468697320697320612074657374206d657373616765", result.getCosePayload(HEX));
        assertEquals("5468697320697320612074657374206d657373616765", result.getMessage(HEX));
        assertEquals("VGhpcyBpcyBhIHRlc3QgbWVzc2FnZQ==", result.getMessage(BASE64));
        assertEquals("This is a test message", result.getMessage(MessageFormat.TEXT));

        assertEquals("2f1867873147cf53c442435723c17e83beeb8e2153851cd73ccfb1b5e68994a4", result.getEd25519PublicKey(HEX));
        assertEquals("846a5369676e617475726531582aa201276761646472657373581de1b83abf370a14870fdfd6ccb35f8b3e62a68e465ed1e096c5a6f5b9d640565468697320697320612074657374206d657373616765", result.getCosePayload(HEX));
    }

    @Test
    void validSignatureWithAddressWithEmptyAddressAndPublicKey() {
        var sig = "844ca20127676164647265737340a166686173686564f4565468697320697320612074657374206d6573736167655840a6cec002ecec0c7140a029feb9152edb444bbd8a58c6a0a4eceac6a0e30943e53f9ebe029d766a08b4198aaae71d656319fff25780eab816ab0937e6704bb001";
        var key = "a401010327200621582052b92d51dc638d085f8663103d5509f0da29bbee418d75f1f2dc7025d69c9643";

        var p = new CIP30Verifier(sig, key);
        var result = p.verify();

        assertTrue(result.isValid());
        assertTrue(result.getAddress().isEmpty(), "address is NOT baked in (serialised in CIP-30).");
        assertEquals("This is a test message", result.getMessage(MessageFormat.TEXT));

        assertEquals("52b92d51dc638d085f8663103d5509f0da29bbee418d75f1f2dc7025d69c9643", result.getEd25519PublicKey(HEX));

        assertEquals("846a5369676e6174757265314ca2012767616464726573734040565468697320697320612074657374206d657373616765", result.getCosePayload(HEX));
        assertEquals("a6cec002ecec0c7140a029feb9152edb444bbd8a58c6a0a4eceac6a0e30943e53f9ebe029d766a08b4198aaae71d656319fff25780eab816ab0937e6704bb001", result.getEd25519Signature(HEX));
    }

     @Test
    // probably because public key is not available in signature
    void validSignatureWithoutPublicKey() {
        var sig = "84582aa201276761646472657373581de19090058641fa866e47d656f62be510cb10a90d48b0aafc868f25291ea166686173686564f458ae7b2270726f706f73616c223a2231366436623066393930663563353266393765323338363235623464356362633138333866326439353334313138313664323466643362613234363364666462222c227265717565737465644174223a223734363935373136222c22766f746572223a227374616b6531757867667170767867386167766d6a383665743076326c397a72393370326764667a6332346c797833756a6a6a3873663678763376227d5840ae514d8d246790d728855f69a0ae32b0c5e59f44e00183b20bf110a42d83fa7c209a290b60a65571648220fc36c4efcb9d472e319bf0afdae42fb078085e4206";

        var p = new CIP30Verifier(sig, (String) null);
        var result = p.verify();

        assertFalse(result.isValid());
        assertEquals(NO_PUBLIC_KEY, result.getValidationError().orElseThrow());

        assertTrue(result.getAddress().isEmpty(), "strict.verify()r, address not available.");
        assertNull(result.getMessage(), "strict.verify()r, message not available.");
    }

    @Test
    void validSignatureWitPublicKeyWithEmptyMessage() {
        var sig = "84582aa201276761646472657373581de01d813fd4ab9c1e5f7a35da16f75c2e664edfb2a127fc17a4a7ebbfeea166686173686564f44058406ad1822a992684ed10c2802f2c689516254511e92559f19d5288df96f05d002c560d02e0130f73fe2c762170b185d9f9193c3e1efec5f599cb99dfee662d4f0e";
        var key = "a4010103272006215820c4821499cef96eda9c00cdd0bfbcd2abf7d09436ad424ac7288653a8b4252014";

        var p = new CIP30Verifier(sig, key);
        var result = p.verify();

        assertTrue(result.isValid());

        assertEquals("", result.getMessage(MessageFormat.TEXT), "strict.verify()r, message not available.");
        assertEquals("stake_test1uqwcz0754wwpuhm6xhdpda6u9enyahaj5ynlc9ay5l4mlms4pyqyg", result.getAddress(AddressFormat.TEXT).orElseThrow());
    }

    @Test
    // probably because public key is not available in signature
    void signatureIsValidWithoutKeyAndExplicitKeyIsNotPassed() {
        var sig = "84582aa201276761646472657373581de19090058641fa866e47d656f62be510cb10a90d48b0aafc868f25291ea166686173686564f458ae7b2270726f706f73616c223a2231366436623066393930663563353266393765323338363235623464356362633138333866326439353334313138313664323466643362613234363364666462222c227265717565737465644174223a223734363935373136222c22766f746572223a227374616b6531757867667170767867386167766d6a383665743076326c397a72393370326764667a6332346c797833756a6a6a3873663678763376227d5840ae514d8d246790d728855f69a0ae32b0c5e59f44e00183b20bf110a42d83fa7c209a290b60a65571648220fc36c4efcb9d472e319bf0afdae42fb078085e4206";

        var p = new CIP30Verifier(sig);
        var result = p.verify();

        assertFalse(result.isValid());

        assertNull(result.getAddress().orElse(null));
        assertNull(result.getEd25519PublicKey());
        assertNull(result.getMessage());
        assertNull(result.getCosePayload());
        assertNull(result.getEd25519PublicKey(HEX));
    }

    @Test
    void checkIfExceptionsAreThrown() {
        var sig = "844ca20127676164647265737340a166686173686564f4565468697320697320612074657374206d6573736167655840a6cec002ecec0c7140a029feb9152edb444bbd8a58c6a0a4eceac6a0e30943e53f9ebe029d766a08b4198aaae71d656319fff25780eab816ab0937e6704bb001";
        var key = "a401010327200621582052b92d51dc638d085f8663103d5509f0da29bbee418d75f1f2dc7025d69c9643";

        var p = new CIP30Verifier(sig, key);
        var result = p.verify();

        assertThrows(IllegalArgumentException.class, () -> {
            result.getEd25519PublicKey(null, UTF_8);
        });
        assertThrows(IllegalArgumentException.class, () -> {
            result.getEd25519PublicKey(HEX, null);
        });
        assertThrows(IllegalArgumentException.class, () -> {
            result.getEd25519PublicKey(null, null);
        });
    }

    @Test
    void invalidSignatureCheck() {
        // correct: 84582aa201276761646472657373581de1b83(AB)f370a14870fdfd6ccb35f8b3e62a68e465ed1e096c5a6f5b9d6a166686173686564f4565468697320697320612074657374206d657373616765584042e2bfc4e1929769a0501b884f66794ae3485860f42c01b70fac37f75e40af074c6b2a61b04c6cf8a493c0dced1455b4f1129dbf653ad9801c52ce49ff6d5a0e
        var sig = "84582aa201276761646472657373581de1b8344f370a14870fdfd6ccb35f8b3e62a68e465ed1e096c5a6f5b9d6a166686173686564f4565468697320697320612074657374206d657373616765584042e2bfc4e1929769a0501b884f66794ae3485860f42c01b70fac37f75e40af074c6b2a61b04c6cf8a493c0dced1455b4f1129dbf653ad9801c52ce49ff6d5a0e";
        var key = "a401010327200621582052b92d51dc638d085f8663103d5509f0da29bbee418d75f1f2dc7025d69c9643";

        var p = new CIP30Verifier(sig, key);
        var result = p.verify();

        assertFalse(result.isValid(), "signature is invalid and should fail to validate");
    }

    @Test
    void publicKeysMismatch() {
        var sig = "84582aa201276761646472657373581de1b83abf370a14870fdfd6ccb35f8b3e62a68e465ed1e096c5a6f5b9d6a166686173686564f4565468697320697320612074657374206d657373616765584042e2bfc4e1929769a0501b884f66794ae3485860f42c01b70fac37f75e40af074c6b2a61b04c6cf8a493c0dced1455b4f1129dbf653ad9801c52ce49ff6d5a0e";
        //var key = "c4821499cef96eda9c00cdd0bfbcd2abf7d09436ad424ac7288653a8b4252014";
        var key = "a4010103272006215820a5f73966e73d0bb9eadc75c5857eafd054a0202d716ac6dde00303ee9c0019e3";

        var p = new CIP30Verifier(sig, key);

        var result = p.verify();

        assertFalse(result.isValid(), "ED 25519 public key within signature doesn't match with passed in key");
    }

}
