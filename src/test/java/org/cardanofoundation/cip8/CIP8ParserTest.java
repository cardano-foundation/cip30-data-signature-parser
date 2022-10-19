package org.cardanofoundation.cip8;

import com.bloxbean.cardano.client.address.util.AddressUtil;
import com.bloxbean.cardano.client.exception.AddressExcepion;
import org.junit.jupiter.api.Test;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.cardanofoundation.cip8.Format.*;
import static org.cardanofoundation.cip8.MoreHex.from;
import static org.junit.jupiter.api.Assertions.*;

class CIP8ParserTest {

    @Test
    void parseWorksFine() throws AddressExcepion {
        var sig = "84582aa201276761646472657373581de1b83abf370a14870fdfd6ccb35f8b3e62a68e465ed1e096c5a6f5b9d6a166686173686564f4565468697320697320612074657374206d657373616765584042e2bfc4e1929769a0501b884f66794ae3485860f42c01b70fac37f75e40af074c6b2a61b04c6cf8a493c0dced1455b4f1129dbf653ad9801c52ce49ff6d5a0e";
        var key = "a40101032720062158202f1867873147cf53c442435723c17e83beeb8e2153851cd73ccfb1b5e68994a4";

        var p = new CIP8Parser(sig, key);
        var result = p.parse();

        assertTrue(result.isValid());

        assertArrayEquals(from("e1b83abf370a14870fdfd6ccb35f8b3e62a68e465ed1e096c5a6f5b9d6"), result.getAddress().orElseThrow());

        assertEquals("stake1uxur40ehpg2gwr7l6mxtxhut8e32drjxtmg7p9k95m6mn4s0tdy6k", AddressUtil.bytesToAddress(result.getAddress().orElseThrow()));

        assertEquals("846a5369676e617475726531582aa201276761646472657373581de1b83abf370a14870fdfd6ccb35f8b3e62a68e465ed1e096c5a6f5b9d640565468697320697320612074657374206d657373616765", result.getCosePayload(HEX, UTF_8).orElseThrow());
        assertEquals("5468697320697320612074657374206d657373616765", result.getMessage(HEX).orElseThrow());
        assertEquals("VGhpcyBpcyBhIHRlc3QgbWVzc2FnZQ==", result.getMessage(BASE64).orElseThrow());
        assertEquals("This is a test message", result.getMessage(TEXT).orElseThrow());

        assertEquals("2f1867873147cf53c442435723c17e83beeb8e2153851cd73ccfb1b5e68994a4", result.getPublicKey(HEX).orElseThrow());
        assertEquals("846a5369676e617475726531582aa201276761646472657373581de1b83abf370a14870fdfd6ccb35f8b3e62a68e465ed1e096c5a6f5b9d640565468697320697320612074657374206d657373616765", result.getCosePayload(HEX).orElseThrow());
    }

}
