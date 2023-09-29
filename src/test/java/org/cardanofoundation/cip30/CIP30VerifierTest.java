package org.cardanofoundation.cip30;

import org.junit.jupiter.api.Test;

import static com.bloxbean.cardano.client.util.HexUtil.decodeHexString;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.cardanofoundation.cip30.MessageFormat.BASE64;
import static org.cardanofoundation.cip30.MessageFormat.HEX;
import static org.cardanofoundation.cip30.ValidationError.UNKNOWN;
import static org.junit.jupiter.api.Assertions.*;

class CIP30VerifierTest {

    @Test
    void validSignatureWithAddressAndPublicKey1() {
        var sig = "84584aa3012704581de11d813fd4ab9c1e5f7a35da16f75c2e664edfb2a127fc17a4a7ebbfee6761646472657373581de11d813fd4ab9c1e5f7a35da16f75c2e664edfb2a127fc17a4a7ebbfeea166686173686564f45901740a202020207b0a202020202020202022757269223a202268747470733a2f2f65766f74696e672e63617264616e6f2e6f72672f766f6c7461697265222c0a202020202020202022616374696f6e223a20224c4f47494e222c0a202020202020202022616374696f6e54657874223a20224c6f67696e222c0a202020202020202022736c6f74223a2022313034323536313535222c0a20202020202020202264617461223a207b0a2020202020202020202020202261646472657373223a20227374616b6531757977637a3037353477777075686d36786864706461367539656e796168616a35796e6c63396179356c346d6c6d736a74777a7134222c0a202020202020202020202020226576656e74223a202243465f53554d4d49545f323032335f5445535432222c0a202020202020202020202020226e6574776f726b223a20224d41494e222c0a20202020202020202020202022726f6c65223a2022564f544552220a20202020202020207d0a2020207d0a5840ed875c0a7067c6a50a73195d9e86e6d8d4908de0bb209126a5193ff974844332b307c9a4f9a38978b973b400268cf1bc40bb8326f2ad954ffa262f7c663ff706";
        var key = "a5010102581de01d813fd4ab9c1e5f7a35da16f75c2e664edfb2a127fc17a4a7ebbfee03272006215820c4821499cef96eda9c00cdd0bfbcd2abf7d09436ad424ac7288653a8b4252014";

        var p = new CIP30Verifier(sig, key);

        var result = p.verify();

        assertTrue(result.isValid());

        assertTrue(result.getAddress().isPresent(), "Optional address is included in the signature...");

        assertEquals("stake1uywcz0754wwpuhm6xhdpda6u9enyahaj5ynlc9ay5l4mlmsjtwzq4", result.getAddress(AddressFormat.TEXT).orElseThrow());
        assertTrue(result.getMessage(MessageFormat.TEXT).contains("LOGIN"));
    }

    @Test
    void validSignatureWithAddressAndPublicKey2() {
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
    void validSignatureWitPublicKeyWithEmptyMessage() {
        var sig = "84582aa201276761646472657373581de01d813fd4ab9c1e5f7a35da16f75c2e664edfb2a127fc17a4a7ebbfeea166686173686564f44058406ad1822a992684ed10c2802f2c689516254511e92559f19d5288df96f05d002c560d02e0130f73fe2c762170b185d9f9193c3e1efec5f599cb99dfee662d4f0e";
        var key = "a4010103272006215820c4821499cef96eda9c00cdd0bfbcd2abf7d09436ad424ac7288653a8b4252014";

        var p = new CIP30Verifier(sig, key);
        var result = p.verify();

        assertTrue(result.isValid());

        assertEquals("", result.getMessage(MessageFormat.TEXT), "message not available.");
        assertEquals("stake_test1uqwcz0754wwpuhm6xhdpda6u9enyahaj5ynlc9ay5l4mlms4pyqyg", result.getAddress(AddressFormat.TEXT).orElseThrow());
    }

    @Test
    void validSignatureWithoutPublicKeyInKid4_1() {
        var sig = "84582aa201276761646472657373581de19090058641fa866e47d656f62be510cb10a90d48b0aafc868f25291ea166686173686564f458ae7b2270726f706f73616c223a2231366436623066393930663563353266393765323338363235623464356362633138333866326439353334313138313664323466643362613234363364666462222c227265717565737465644174223a223734363935373136222c22766f746572223a227374616b6531757867667170767867386167766d6a383665743076326c397a72393370326764667a6332346c797833756a6a6a3873663678763376227d5840ae514d8d246790d728855f69a0ae32b0c5e59f44e00183b20bf110a42d83fa7c209a290b60a65571648220fc36c4efcb9d472e319bf0afdae42fb078085e4206";

        var p = new CIP30Verifier(sig);
        var result = p.verify();

        assertFalse(result.isValid());
        assertTrue(result.getAddress().isPresent(), "address is available.");

        assertEquals("stake1uxgfqpvxg8agvmj86et0v2l9zr93p2gdfzc24lyx3ujjj8sf6xv3v", result.getAddress(AddressFormat.TEXT).orElseThrow());

        assertEquals("{\"proposal\":\"16d6b0f990f5c52f97e238625b4d5cbc1838f2d953411816d24fd3ba2463dfdb\",\"requestedAt\":\"74695716\",\"voter\":\"stake1uxgfqpvxg8agvmj86et0v2l9zr93p2gdfzc24lyx3ujjj8sf6xv3v\"}", result.getMessage(MessageFormat.TEXT));
    }

    @Test
    void validSignatureWithoutPublicKeyInKid4_2() {
        var sig = "84582aa201276761646472657373581de19090058641fa866e47d656f62be510cb10a90d48b0aafc868f25291ea166686173686564f458ae7b2270726f706f73616c223a2231366436623066393930663563353266393765323338363235623464356362633138333866326439353334313138313664323466643362613234363364666462222c227265717565737465644174223a223734363935373136222c22766f746572223a227374616b6531757867667170767867386167766d6a383665743076326c397a72393370326764667a6332346c797833756a6a6a3873663678763376227d5840ae514d8d246790d728855f69a0ae32b0c5e59f44e00183b20bf110a42d83fa7c209a290b60a65571648220fc36c4efcb9d472e319bf0afdae42fb078085e4206";

        var p = new CIP30Verifier(sig, (String) null);
        var result = p.verify();

        assertFalse(result.isValid());
        assertEquals(UNKNOWN, result.getValidationError().orElseThrow());

        assertTrue(result.getAddress().isPresent(), "address is available.");
        assertEquals("stake1uxgfqpvxg8agvmj86et0v2l9zr93p2gdfzc24lyx3ujjj8sf6xv3v", result.getAddress(AddressFormat.TEXT).orElseThrow());

        assertEquals("{\"proposal\":\"16d6b0f990f5c52f97e238625b4d5cbc1838f2d953411816d24fd3ba2463dfdb\",\"requestedAt\":\"74695716\",\"voter\":\"stake1uxgfqpvxg8agvmj86et0v2l9zr93p2gdfzc24lyx3ujjj8sf6xv3v\"}", result.getMessage(MessageFormat.TEXT));
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
        //var key = "c4821499cef96eda9c00cdd0bfbcd2abf7d09436ad424ac7288653a8b4252014"; // correct key
        var key = "a4010103272006215820a5f73966e73d0bb9eadc75c5857eafd054a0202d716ac6dde00303ee9c0019e3"; // incorrect key

        var p = new CIP30Verifier(sig, key);

        var result = p.verify();

        assertFalse(result.isValid(), "ED 25519 public key within signature doesn't match with passed in key");
    }

    @Test
    void publicKeysMismatch2() {
        var sig = "84584aa3012704581de01d813fd4ab9c1e5f7a35da16f75c2e664edfb2a127fc17a4a7ebbfee6761646472657373581de01d813fd4ab9c1e5f7a35da16f75c2e664edfb2a127fc17a4a7ebbfeea166686173686564f458e67b22616374696f6e223a2246554c4c5f4d455441444154415f5343414e222c22616374696f6e54657874223a2246554c4c5f4d455441444154415f5343414e222c22757269223a22687474703a2f2f6c6f63616c686f73743a383038302f6170692f61646d696e2f66756c6c2d6d657461646174612d7363616e222c2264617461223a7b2261646472657373223a227374616b655f7465737431757177637a3037353477777075686d36786864706461367539656e796168616a35796e6c63396179356c346d6c6d73347079717967222c226e6574776f726b223a2250524550524f44227d7d5840b69fbe15912f0dabd46f6a3a5eebae58acefc7c80e82da70803c52860293d1fa53c9cb0a04758cf36fbec726835cac5e519b60ebd2c2cd04d66ad94c46b07604";
        var key = "a4010103272006215820c4821499cef96eda9c00cdd0bfbcd2abf7d09436ad424ac7288653a8b4252014";

        var p = new CIP30Verifier(sig, key);

        var result = p.verify();

        assertFalse(result.isValid(), "ED 25519 public key within signature doesn't match with passed in key");
    }

    @Test
    // typhon 3.0.14 wallet case -> we should be ignoring now KID4 in protected headers
    void signatureWithOptionalKid4SetIncorrectly() {
        var sig = "84584da30127045820c4821499cef96eda9c00cdd0bfbcd2abf7d09436ad424ac7288653a8b42520146761646472657373581de01d813fd4ab9c1e5f7a35da16f75c2e664edfb2a127fc17a4a7ebbfeea166686173686564f44568656c6c6f5840c0d5f54ab847cb78e8aeff10691bb1dcc5eec9a52fbf9011a0cfe89a51c53c2e22f408708da3a2fb35bf8f518f63e79ae8388f12b198cb1bdbd0d40b72081b0d";
        var key = "a4010103272006215820c4821499cef96eda9c00cdd0bfbcd2abf7d09436ad424ac7288653a8b4252014";

        var p = new CIP30Verifier(sig, key);

        var result = p.verify();

        assertTrue(result.isValid());
    }

}
