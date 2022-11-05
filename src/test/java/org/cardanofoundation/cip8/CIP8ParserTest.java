package org.cardanofoundation.cip8;

import com.bloxbean.cardano.client.exception.AddressExcepion;
import org.junit.jupiter.api.Test;

import static com.bloxbean.cardano.client.address.util.AddressUtil.bytesToAddress;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.cardanofoundation.cip8.Format.*;
import static org.cardanofoundation.cip8.MoreHex.from;
import static org.cardanofoundation.cip8.ValidationError.NO_PUBLIC_KEY;
import static org.junit.jupiter.api.Assertions.*;

class CIP8ParserTest {

    @Test
    void validSignatureWithAddressAndPublicKey() throws AddressExcepion {
        var sig = "84582aa201276761646472657373581de1b83abf370a14870fdfd6ccb35f8b3e62a68e465ed1e096c5a6f5b9d6a166686173686564f4565468697320697320612074657374206d657373616765584042e2bfc4e1929769a0501b884f66794ae3485860f42c01b70fac37f75e40af074c6b2a61b04c6cf8a493c0dced1455b4f1129dbf653ad9801c52ce49ff6d5a0e";
        var key = "a40101032720062158202f1867873147cf53c442435723c17e83beeb8e2153851cd73ccfb1b5e68994a4";

        var p = new CIP8Parser(sig, key);

        var result = p.parse();

        assertTrue(result.isValid());

        assertTrue(result.getAddress().isPresent(), "Optional address is included in the signature...");

        assertArrayEquals(from("e1b83abf370a14870fdfd6ccb35f8b3e62a68e465ed1e096c5a6f5b9d6"), result.getAddress().orElseThrow());
        assertEquals("a40101032720062158202f1867873147cf53c442435723c17e83beeb8e2153851cd73ccfb1b5e68994a4", p.getPublicKey().orElseThrow());

        assertArrayEquals(from("2f1867873147cf53c442435723c17e83beeb8e2153851cd73ccfb1b5e68994a4"), result.getPublicKey());
        assertArrayEquals(from("42e2bfc4e1929769a0501b884f66794ae3485860f42c01b70fac37f75e40af074c6b2a61b04c6cf8a493c0dced1455b4f1129dbf653ad9801c52ce49ff6d5a0e"), result.getSignature());
        assertArrayEquals(from("846a5369676e617475726531582aa201276761646472657373581de1b83abf370a14870fdfd6ccb35f8b3e62a68e465ed1e096c5a6f5b9d640565468697320697320612074657374206d657373616765"), result.getCosePayload());

        assertEquals("stake1uxur40ehpg2gwr7l6mxtxhut8e32drjxtmg7p9k95m6mn4s0tdy6k", bytesToAddress(result.getAddress().orElseThrow()));

        assertEquals("846a5369676e617475726531582aa201276761646472657373581de1b83abf370a14870fdfd6ccb35f8b3e62a68e465ed1e096c5a6f5b9d640565468697320697320612074657374206d657373616765", result.getCosePayload(HEX));
        assertEquals("5468697320697320612074657374206d657373616765", result.getMessage(HEX));
        assertEquals("VGhpcyBpcyBhIHRlc3QgbWVzc2FnZQ==", result.getMessage(BASE64));
        assertEquals("This is a test message", result.getMessage(TEXT));

        assertEquals("2f1867873147cf53c442435723c17e83beeb8e2153851cd73ccfb1b5e68994a4", result.getPublicKey(HEX));
        assertEquals("846a5369676e617475726531582aa201276761646472657373581de1b83abf370a14870fdfd6ccb35f8b3e62a68e465ed1e096c5a6f5b9d640565468697320697320612074657374206d657373616765", result.getCosePayload(HEX));
    }

    @Test
    void validSignatureWithAddressWithEmptyAddressAndPublicKey() {
        var sig = "844ca20127676164647265737340a166686173686564f4565468697320697320612074657374206d6573736167655840a6cec002ecec0c7140a029feb9152edb444bbd8a58c6a0a4eceac6a0e30943e53f9ebe029d766a08b4198aaae71d656319fff25780eab816ab0937e6704bb001";
        var key = "a401010327200621582052b92d51dc638d085f8663103d5509f0da29bbee418d75f1f2dc7025d69c9643";

        var p = new CIP8Parser(sig, key);
        var result = p.parse();

        assertTrue(result.getAddress().isEmpty(), "address is NOT baked in (serialised in CIP-8).");

        assertEquals("This is a test message", result.getMessage(TEXT));
        assertEquals("52b92d51dc638d085f8663103d5509f0da29bbee418d75f1f2dc7025d69c9643", result.getPublicKey(HEX));
        assertEquals("846a5369676e6174757265314ca2012767616464726573734040565468697320697320612074657374206d657373616765", result.getCosePayload(HEX));
        assertEquals("a6cec002ecec0c7140a029feb9152edb444bbd8a58c6a0a4eceac6a0e30943e53f9ebe029d766a08b4198aaae71d656319fff25780eab816ab0937e6704bb001", result.getSignature(HEX));
    }

     @Test
    // probably because public key is not available in signature
    void validSignatureWithoutPublicKey() {
        var sig = "84582aa201276761646472657373581de19090058641fa866e47d656f62be510cb10a90d48b0aafc868f25291ea166686173686564f458ae7b2270726f706f73616c223a2231366436623066393930663563353266393765323338363235623464356362633138333866326439353334313138313664323466643362613234363364666462222c227265717565737465644174223a223734363935373136222c22766f746572223a227374616b6531757867667170767867386167766d6a383665743076326c397a72393370326764667a6332346c797833756a6a6a3873663678763376227d5840ae514d8d246790d728855f69a0ae32b0c5e59f44e00183b20bf110a42d83fa7c209a290b60a65571648220fc36c4efcb9d472e319bf0afdae42fb078085e4206";

        var p = new CIP8Parser(sig, (String) null);
        var result = p.parse();

        assertFalse(result.isValid());
        assertEquals(NO_PUBLIC_KEY, result.getValidationError().orElseThrow());

        assertTrue(result.getAddress().isEmpty(), "strict parser, address not available.");
        assertNull(result.getMessage(), "strict parser, message not available.");
    }

    @Test
    void validSignatureWitPublicKeyWithEmptyMessage() throws AddressExcepion {
        var sig = "84582aa201276761646472657373581de01d813fd4ab9c1e5f7a35da16f75c2e664edfb2a127fc17a4a7ebbfeea166686173686564f44058406ad1822a992684ed10c2802f2c689516254511e92559f19d5288df96f05d002c560d02e0130f73fe2c762170b185d9f9193c3e1efec5f599cb99dfee662d4f0e";
        var key = "a4010103272006215820c4821499cef96eda9c00cdd0bfbcd2abf7d09436ad424ac7288653a8b4252014";

        var p = new CIP8Parser(sig, key);
        var result = p.parse();

        assertTrue(result.isValid());

        assertEquals("", result.getMessage(TEXT), "strict parser, message not available.");
        assertEquals("stake_test1uqwcz0754wwpuhm6xhdpda6u9enyahaj5ynlc9ay5l4mlms4pyqyg", bytesToAddress(result.getAddress().orElseThrow()));
    }

    @Test
    // probably because public key is not available in signature
    void signatureIsValidWithoutKeyAndExplicitKeyIsNotPassed() {
        var sig = "84582aa201276761646472657373581de19090058641fa866e47d656f62be510cb10a90d48b0aafc868f25291ea166686173686564f458ae7b2270726f706f73616c223a2231366436623066393930663563353266393765323338363235623464356362633138333866326439353334313138313664323466643362613234363364666462222c227265717565737465644174223a223734363935373136222c22766f746572223a227374616b6531757867667170767867386167766d6a383665743076326c397a72393370326764667a6332346c797833756a6a6a3873663678763376227d5840ae514d8d246790d728855f69a0ae32b0c5e59f44e00183b20bf110a42d83fa7c209a290b60a65571648220fc36c4efcb9d472e319bf0afdae42fb078085e4206";

        var p = new CIP8Parser(sig);
        var result = p.parse();

        assertFalse(result.isValid());

        assertNull(result.getAddress().orElse(null));
        assertNull(result.getPublicKey());
        assertNull(result.getMessage());
        assertNull(result.getCosePayload());
        assertNull(result.getPublicKey(HEX));
    }

    @Test
    void checkIfExceptionsAreThrown() {
        var sig = "844ca20127676164647265737340a166686173686564f4565468697320697320612074657374206d6573736167655840a6cec002ecec0c7140a029feb9152edb444bbd8a58c6a0a4eceac6a0e30943e53f9ebe029d766a08b4198aaae71d656319fff25780eab816ab0937e6704bb001";
        var key = "a401010327200621582052b92d51dc638d085f8663103d5509f0da29bbee418d75f1f2dc7025d69c9643";

        var p = new CIP8Parser(sig, key);
        var result = p.parse();

        assertThrows(IllegalArgumentException.class, () -> {
            result.getPublicKey(null, UTF_8);
        });
        assertThrows(IllegalArgumentException.class, () -> {
            result.getPublicKey(HEX, null);
        });
        assertThrows(IllegalArgumentException.class, () -> {
            result.getPublicKey(null, null);
        });
    }

    @Test
    void invalidFormatCheck() {
        // correct: 84582aa201276761646472657373581de1b83(AB)f370a14870fdfd6ccb35f8b3e62a68e465ed1e096c5a6f5b9d6a166686173686564f4565468697320697320612074657374206d657373616765584042e2bfc4e1929769a0501b884f66794ae3485860f42c01b70fac37f75e40af074c6b2a61b04c6cf8a493c0dced1455b4f1129dbf653ad9801c52ce49ff6d5a0e
        var sig = "84582aa201276761646472657373581de1b8344f370a14870fdfd6ccb35f8b3e62a68e465ed1e096c5a6f5b9d6a166686173686564f4565468697320697320612074657374206d657373616765584042e2bfc4e1929769a0501b884f66794ae3485860f42c01b70fac37f75e40af074c6b2a61b04c6cf8a493c0dced1455b4f1129dbf653ad9801c52ce49ff6d5a0e";
        var key = "a401010327200621582052b92d51dc638d085f8663103d5509f0da29bbee418d75f1f2dc7025d69c9643";

        var p = new CIP8Parser(sig, key);
        var result = p.parse();

        assertFalse(result.isValid(), "signature is invalid and should fail to validate");
    }

}
