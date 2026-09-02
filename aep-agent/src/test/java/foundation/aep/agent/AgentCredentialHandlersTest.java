package foundation.aep.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import foundation.aep.core.Aep;
import java.net.URI;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.CompletionException;
import org.junit.jupiter.api.Test;

final class AgentCredentialHandlersTest {
    private static final String SERVICE_DID = "did:web:service.example";
    private static final URI RESOURCE = URI.create("https://service.example/private");

    @Test
    void rendersEveryBuiltInCredentialWithoutDisclosingSecrets() {
        assertCredential(AgentCredentialHandlers.oauthBearer(), """
                {"access_token":"bearer-secret","credential_id":"oauth-1",\
                "expires_at":"2027-01-01T00:00:00Z","token_type":"Bearer"}
                """, Map.of("Authorization", "Bearer bearer-secret"));
        assertCredential(AgentCredentialHandlers.apiKey(), """
                {"api_key":"api-secret","credential_id":"api-1",\
                "expires_at":"2027-01-01T00:00:00Z","header":"X-Service-Key"}
                """, Map.of("X-Service-Key", "api-secret"));
        assertCredential(
                AgentCredentialHandlers.basic(), """
                {"credential_id":"basic-1","expires_at":"2027-01-01T00:00:00Z",\
                "password":"basic-secret","username":"agent"}
                """, Map.of("Authorization", "Basic YWdlbnQ6YmFzaWMtc2VjcmV0"));
    }

    @Test
    void rejectsStoredPayloadAndMetadataMismatch() {
        AgentCredentialHandler handler = AgentCredentialHandlers.apiKey();
        AgentCredential record = new AgentCredential(
                SERVICE_DID, Aep.GRANT_TYPE_API_KEY, "different", Instant.parse("2027-01-01T00:00:00Z"), """
                {"api_key":"api-secret","credential_id":"api-1",\
                "expires_at":"2027-01-01T00:00:00Z","header":"X-Service-Key"}
                """);

        assertThrows(IllegalArgumentException.class, () -> handler.authorizationHeaders(record, RESOURCE));
    }

    @Test
    void inMemoryStoreRejectsCredentialIdentifierReassignment() {
        AgentCredentialStore store = AgentCredentialStore.inMemory();
        AgentCredential first = new AgentCredential(
                SERVICE_DID, Aep.GRANT_TYPE_API_KEY, "credential-1", null, "{\"version\":\"first\"}");
        AgentCredential replacement = new AgentCredential(
                SERVICE_DID, Aep.GRANT_TYPE_API_KEY, "credential-1", null, "{\"version\":\"second\"}");
        store.save(first).toCompletableFuture().join();

        assertThrows(
                CompletionException.class,
                () -> store.save(replacement).toCompletableFuture().join());
        assertEquals(
                first,
                store.find(SERVICE_DID, Aep.GRANT_TYPE_API_KEY)
                        .toCompletableFuture()
                        .join()
                        .orElseThrow());
    }

    private static void assertCredential(
            AgentCredentialHandler handler, String response, Map<String, String> expectedHeaders) {
        AgentCredential credential = handler.parse(SERVICE_DID, response);

        assertEquals(expectedHeaders, handler.authorizationHeaders(credential, RESOURCE));
        expectedHeaders
                .values()
                .forEach(secret -> assertFalse(credential.toString().contains(secret)));
    }
}
