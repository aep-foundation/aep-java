package foundation.aep.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import org.junit.jupiter.api.Test;

final class DidWebTest {
    @Test
    void resolvesRootAndPathIdentifiers() {
        assertEquals(URI.create("https://example.com/.well-known/did.json"), DidWeb.documentUri("did:web:example.com"));
        assertEquals(
                URI.create("https://example.com:8443/agents/alice/did.json"),
                DidWeb.documentUri("did:web:example.com%3A8443:agents:alice"));
    }

    @Test
    void preservesPlusAndRejectsEncodedPathSeparators() {
        assertEquals(
                URI.create("https://example.com/agent+one/did.json"),
                DidWeb.documentUri("did:web:example.com:agent+one"));
        assertThrows(IllegalArgumentException.class, () -> DidWeb.documentUri("did:web:example.com:agent%2Fone"));
    }

    @Test
    void bindsDidWebToItsOrigin() {
        assertTrue(DidWeb.bindsOrigin("did:web:example.com", URI.create("https://example.com")));
        assertFalse(DidWeb.bindsOrigin("did:web:example.com", URI.create("https://other.example")));
    }
}
