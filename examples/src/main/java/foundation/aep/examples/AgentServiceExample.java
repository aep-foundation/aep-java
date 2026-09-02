package foundation.aep.examples;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import foundation.aep.agent.AepAgent;
import foundation.aep.agent.AepServiceSession;
import foundation.aep.agent.AgentAuthentication;
import foundation.aep.agent.AgentIdentity;
import foundation.aep.core.Aep;
import foundation.aep.core.ClaimValues;
import foundation.aep.core.ClientAssertions;
import foundation.aep.core.ContactAddressPrimary;
import foundation.aep.core.GrantResponses;
import foundation.aep.core.InspectDocument;
import foundation.aep.core.RevokeRequest;
import foundation.aep.httpserver.AepHttpServer;
import foundation.aep.service.AepService;
import foundation.aep.service.AepServiceHttpHandler;
import foundation.aep.service.ClientAssertionVerifier;
import foundation.aep.service.ServiceCredentialStore;
import foundation.aep.service.StoredCredentialGrantType;
import foundation.aep.service.StoredCredentialGrantTypes;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

public final class AgentServiceExample {
    private static final String AGENT_DID = "did:web:agent.example";
    private static final String API_KEY_HEADER = "X-API-Key";
    private static final int HTTP_UNAUTHORIZED = 401;

    private AgentServiceExample() {}

    public static void main(String[] arguments) throws Exception {
        ECKey agentKey = generateKey("agent-key");
        HttpServer server = HttpServer.create(
                new InetSocketAddress("127.0.0.1", 0), 0); // NOPMD - Explicit loopback-only example server.
        URI origin = URI.create("http://127.0.0.1:" + server.getAddress().getPort());
        String serviceDid = "did:web:127.0.0.1%3A" + server.getAddress().getPort();

        InspectDocument document = inspectDocument(serviceDid);
        ServiceCredentialStore credentialStore = ServiceCredentialStore.inMemory();
        StoredCredentialGrantType apiKey = StoredCredentialGrantTypes.apiKey(
                document.commands().grantTypesConfig().get(Aep.GRANT_TYPE_API_KEY),
                (request, context) -> CompletableFuture.completedFuture(new GrantResponses.ApiKey(
                        "example-" + UUID.randomUUID(),
                        UUID.randomUUID().toString(),
                        context.now().plus(1, ChronoUnit.HOURS).toString(),
                        API_KEY_HEADER,
                        request.requestedScopes())),
                credentialStore);
        AepService service = AepService.builder(
                        document,
                        ClientAssertionVerifier.withKeyResolver(
                                (assertion, claims, context) -> resolveAgentKey(claims.issuer(), agentKey)))
                .allowInsecureLoopback(true)
                .storedCredentialGrantType(apiKey)
                .build();
        AepServiceHttpHandler handler = new AepServiceHttpHandler(service);
        AepHttpServer.register(server, handler);
        URI profile = origin.resolve("/profile");
        server.createContext("/profile", AepHttpServer.protect(handler, origin, AgentServiceExample::profile));
        server.start();

        try {
            JdkAepTransport transport = new JdkAepTransport();
            AepAgent agent = AepAgent.builder()
                    .inspectTransport(transport)
                    .commandTransport(transport)
                    .identityProvider((serviceOrigin, advertisedDid) ->
                            CompletableFuture.completedFuture(new AgentIdentity(
                                    AGENT_DID,
                                    claims -> CompletableFuture.completedFuture(
                                            ClientAssertions.sign(claims, agentKey, AGENT_DID + "#key-1", true)))))
                    .allowInsecureLoopback(true)
                    .build();
            AepServiceSession session = agent.service(origin);

            var inspection = session.inspect().join();
            System.out.println("Inspected " + inspection.document().service().did()); // NOPMD - Example output.

            var enrollment = session.enroll(claims()).join();
            System.out.println("Enrollment status: " + enrollment.status().value()); // NOPMD - Example output.

            var grant = session.grant(Aep.GRANT_TYPE_API_KEY, List.of("profile:read"))
                    .join();
            String credentialId = grant.credential().orElseThrow().credentialId();
            System.out.println("Issued API-key credential: " + credentialId); // NOPMD - Example output.

            AgentAuthentication authentication = session.authenticate(profile).join();
            HttpResponse<String> response = getProfile(transport, profile, authentication);
            System.out.println( // NOPMD - Example output.
                    "Protected profile: " + response.statusCode() + " " + response.body());

            session.revoke(RevokeRequest.credential(Aep.GRANT_TYPE_API_KEY, credentialId))
                    .join();
            System.out.println("Revoked credential: " + credentialId); // NOPMD - Example output.
            HttpResponse<String> rejected = getProfile(transport, profile, authentication);
            if (rejected.statusCode() != HTTP_UNAUTHORIZED) {
                throw new IllegalStateException("The revoked example credential was accepted.");
            }
        } finally {
            server.stop(0);
        }
    }

    private static InspectDocument inspectDocument(String serviceDid) {
        InspectDocument.GrantTypeConfig apiKey = new InspectDocument.GrantTypeConfig(
                null, "3600", List.of(API_KEY_HEADER), null, List.of("profile:read"), "true", null, null);
        return InspectDocument.builder()
                .version(Aep.VERSION)
                .authentication(new InspectDocument.Authentication(List.of(Aep.GRANT_TYPE_API_KEY)))
                .bindings(new InspectDocument.Bindings(List.of("http")))
                .claims(new InspectDocument.Claims(
                        List.of(
                                Aep.CLAIM_CONTACT_ADDRESS_PRIMARY,
                                Aep.CLAIM_CONTACT_EMAIL,
                                Aep.CLAIM_PERSON_FIRST_NAME,
                                Aep.CLAIM_PERSON_LAST_NAME),
                        List.of(),
                        List.of()))
                .commands(new InspectDocument.Commands(
                        List.of("enroll", "grant", "inspect", "revoke", "status"),
                        List.of(Aep.GRANT_TYPE_API_KEY),
                        Map.of(Aep.GRANT_TYPE_API_KEY, apiKey)))
                .core(new InspectDocument.Core(Aep.REQUIRED_SIGNING_ALGORITHMS))
                .http(new InspectDocument.Http("/aep/", null))
                .identity(new InspectDocument.Identity(List.of(Aep.IDENTITY_METHOD_DID_WEB)))
                .service(new InspectDocument.Service(serviceDid))
                .build();
    }

    private static ClaimValues claims() {
        return ClaimValues.builder()
                .contactAddressPrimary(new ContactAddressPrimary(
                        "San Francisco", "US", "Avery", "Agent", "1 Market Street", null, null, "94105", "CA"))
                .contactEmail("avery@example.com")
                .personFirstName("Avery")
                .personLastName("Agent")
                .build();
    }

    private static void profile(HttpExchange exchange) throws IOException {
        byte[] body = "AEP-authenticated profile".getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        exchange.sendResponseHeaders(200, body.length);
        try (exchange;
                var output = exchange.getResponseBody()) {
            output.write(body);
        }
    }

    private static HttpResponse<String> getProfile(
            JdkAepTransport transport, URI profile, AgentAuthentication authentication)
            throws IOException, InterruptedException {
        HttpRequest.Builder request = HttpRequest.newBuilder(profile).GET();
        authentication.headers().forEach((name, values) -> values.forEach(value -> request.header(name, value)));
        return transport.send(request.build());
    }

    private static ECKey generateKey(String id) {
        try {
            return new ECKeyGenerator(Curve.P_256).keyID(id).generate();
        } catch (JOSEException exception) {
            throw new IllegalStateException("Unable to generate the example signing key.", exception);
        }
    }

    private static CompletableFuture<JWK> resolveAgentKey(String agentDid, ECKey agentKey) {
        if (!AGENT_DID.equals(agentDid)) {
            return CompletableFuture.failedFuture(new IllegalArgumentException("Unknown example Agent DID."));
        }
        return CompletableFuture.completedFuture(agentKey.toPublicJWK());
    }
}
