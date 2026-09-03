package foundation.aep.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import foundation.aep.core.Aep;
import foundation.aep.core.AgentStatus;
import foundation.aep.core.ClaimValues;
import foundation.aep.core.ClientAssertionClaims;
import foundation.aep.core.ClientAssertions;
import foundation.aep.core.EnrollRequest;
import foundation.aep.core.GrantRequest;
import foundation.aep.core.InspectDocument;
import foundation.aep.core.RevokeRequest;
import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

final class AepServiceTest {
    private static final Instant NOW = Instant.parse("2026-09-01T12:00:00Z");
    private static final String AGENT_DID = "did:web:agent.example";

    @Test
    void enrollsOnceAndReturnsExistingLifecycleForANewKey() {
        AtomicInteger decisions = new AtomicInteger();
        EnrollmentPolicy policy = (request, now) -> {
            decisions.incrementAndGet();
            return completed(new EnrollmentDecision(AgentStatus.PENDING, true, List.of("contact.email"), List.of()));
        };
        AepService service = serviceBuilder(document(false), policy).build();
        EnrollRequest request = requestWithRequiredClaims();

        ServiceResponse<?> first = service.enroll(request, idempotent("enroll-1", "key-1"))
                .toCompletableFuture()
                .join();
        ServiceResponse<?> second = service.enroll(
                        new EnrollRequest(AGENT_DID, null, null), idempotent("enroll-2", "key-2"))
                .toCompletableFuture()
                .join();

        assertEquals(200, first.status());
        assertEquals(AgentStatus.PENDING, ((foundation.aep.core.EnrollResponse) first.body()).status());
        assertEquals("true", ((foundation.aep.core.EnrollResponse) second.body()).ownerActionRequired());
        assertEquals(1, decisions.get());
    }

    @Test
    void cachesRequirementsUnmetAndDetectsIdempotencyConflict() {
        AepService service =
                serviceBuilder(document(false), EnrollmentPolicy.active()).build();
        EnrollRequest missing = new EnrollRequest(AGENT_DID, null, null);

        ServiceResponse<?> first = service.enroll(missing, idempotent("missing-1", "same-key"))
                .toCompletableFuture()
                .join();
        ServiceResponse<?> replay = service.enroll(missing, idempotent("missing-2", "same-key"))
                .toCompletableFuture()
                .join();
        ServiceResponse<?> conflict = service.enroll(requestWithRequiredClaims(), idempotent("missing-3", "same-key"))
                .toCompletableFuture()
                .join();

        assertEquals(422, first.status());
        assertEquals(List.of("contact.email"), first.problem().requirementsPending());
        assertEquals(first, replay);
        assertEquals(409, conflict.status());
        assertEquals("idempotency_conflict", conflict.problem().code());
    }

    @Test
    void rejectsReplayedAssertionWithoutDisclosingTheCause() {
        AepService service =
                serviceBuilder(document(false), EnrollmentPolicy.active()).build();
        CommandOptions options = CommandOptions.authenticated("status-replay");

        ServiceResponse<?> first = service.status(options).toCompletableFuture().join();
        ServiceResponse<?> second =
                service.status(options).toCompletableFuture().join();

        assertEquals(401, first.status());
        assertEquals(401, second.status());
        assertEquals("not_recognized", second.problem().code());
    }

    @Test
    void rejectsExpirationBoundaryFromCustomVerifier() {
        AepService service = AepService.builder(
                        document(false),
                        (assertion, context) -> completed(new ClientAssertionClaims(
                                AGENT_DID,
                                AGENT_DID,
                                context.serviceDid(),
                                context.operation(),
                                NOW.minusSeconds(60).getEpochSecond(),
                                NOW.minusSeconds(30).getEpochSecond(),
                                "expiration-boundary",
                                null)))
                .clock(Clock.fixed(NOW, ZoneOffset.UTC))
                .clockSkew(java.time.Duration.ofSeconds(30))
                .build();

        ServiceResponse<?> response = service.status(CommandOptions.authenticated("assertion"))
                .toCompletableFuture()
                .join();

        assertEquals(401, response.status());
        assertEquals("not_recognized", response.problem().code());
    }

    @Test
    void grantsAndRevokesThroughTheAdvertisedHandler() {
        RecordingGrantHandler handler = new RecordingGrantHandler();
        AepService service = serviceBuilder(document(true), EnrollmentPolicy.active())
                .grantType(new GrantTypeDefinition("api-key", handler))
                .credentialAuthenticator("api-key", new EmptyAuthenticator())
                .build();
        enroll(service);

        ServiceResponse<Map<String, Object>> grant = service.grant(
                        new GrantRequest("api-key", List.of("purchase")), idempotent("grant-1", "grant-key"))
                .toCompletableFuture()
                .join();
        ServiceResponse<?> revoke = service.revoke(
                        RevokeRequest.credential("api-key", "credential-1"), idempotent("revoke-1", "revoke-key"))
                .toCompletableFuture()
                .join();

        assertEquals(200, grant.status());
        assertEquals("credential-1", grant.body().get("credential_id"));
        assertEquals(200, revoke.status());
        assertEquals(1, handler.revocations.get());
    }

    @Test
    void copiesNestedGrantResponseValues() {
        List<String> scopes = new java.util.ArrayList<>(List.of("purchase"));
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("credential_id", "credential-1");
        response.put("scopes", scopes);

        GrantResult result = new GrantResult("credential-1", response);
        scopes.add("refund");
        response.put("token", "secret");

        assertEquals(Map.of("credential_id", "credential-1", "scopes", List.of("purchase")), result.response());
        assertThrows(
                UnsupportedOperationException.class,
                () -> ((List<?>) result.response().get("scopes")).clear());
    }

    @Test
    void rejectsNonJsonGrantResponseValues() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new GrantResult("credential-1", Map.of("credential_id", "credential-1", "invalid", Double.NaN)));
    }

    @Test
    void revokesEveryAdvertisedGrantTypeWithoutASelectedGrantType() {
        RecordingGrantHandler first = new RecordingGrantHandler();
        RecordingGrantHandler second = new RecordingGrantHandler();
        AepService service = serviceBuilder(
                        documentWithGrantTypes("api-key", "oauth-bearer"), EnrollmentPolicy.active())
                .grantType(new GrantTypeDefinition("api-key", first))
                .credentialAuthenticator("api-key", new EmptyAuthenticator())
                .grantType(new GrantTypeDefinition("oauth-bearer", second))
                .credentialAuthenticator("oauth-bearer", new EmptyAuthenticator())
                .build();
        enroll(service);

        ServiceResponse<?> response = service.revoke(
                        RevokeRequest.forAllGrantTypes(), idempotent("revoke-all", "revoke-all-key"))
                .toCompletableFuture()
                .join();

        assertEquals(200, response.status());
        assertEquals(1, first.revocations.get());
        assertEquals(1, second.revocations.get());
    }

    @Test
    void authenticatesAnActiveAgentWithAResourceBoundAssertion() {
        AepService service = serviceBuilder(documentWithJwtAuthentication(), EnrollmentPolicy.active())
                .inspectUri(URI.create("https://service.example/.well-known/aep"))
                .build();
        enroll(service);
        URI resource = URI.create("https://service.example/orders/1");

        ProtectedResourceResult result = service.authenticate(new ProtectedResourceRequest(
                        Map.of("Authorization", List.of("AEP resource-1")), "GET", resource))
                .toCompletableFuture()
                .join();

        assertTrue(result.authenticated());
        assertEquals(AGENT_DID, result.principal().agentDid());
        assertEquals(AuthenticatedPrincipal.Kind.AEP_JWT, result.principal().kind());
    }

    @Test
    void rejectsAmbiguousCredentialsAndChallengesMissingCredentials() {
        AepService service = serviceBuilder(documentWithJwtAuthentication(), EnrollmentPolicy.active())
                .inspectUri(URI.create("https://service.example/.well-known/aep"))
                .build();
        URI resource = URI.create("https://service.example/orders/1");
        ProtectedResourceResult ambiguous = service.authenticate(new ProtectedResourceRequest(
                        Map.of(
                                "Authorization", List.of("AEP first"),
                                "AEP-Authorization", List.of("AEP second")),
                        "GET",
                        resource))
                .toCompletableFuture()
                .join();
        ProtectedResourceResult missing = service.authenticate(new ProtectedResourceRequest(Map.of(), "GET", resource))
                .toCompletableFuture()
                .join();

        assertEquals("not_recognized", ambiguous.response().problem().code());
        assertEquals("authentication_required", missing.response().problem().code());
        assertTrue(missing.response().headers().get("WWW-Authenticate").get(0).contains("service_did"));
    }

    @Test
    void acceptsIpv6LoopbackOnlyWhenExplicitlyConfigured() {
        AepService service = serviceBuilder(documentWithJwtAuthentication(), EnrollmentPolicy.active())
                .allowInsecureLoopback(true)
                .build();
        URI resource = URI.create("http://[::1]/orders/1");

        ProtectedResourceResult result = service.authenticate(new ProtectedResourceRequest(Map.of(), "GET", resource))
                .toCompletableFuture()
                .join();

        assertEquals("authentication_required", result.response().problem().code());
    }

    @Test
    void consumesReplayEntriesAtomically() {
        ReplayStore store = ReplayStore.inMemory();
        ReplayRecord record = new ReplayRecord(AGENT_DID, "jti", NOW.plusSeconds(60));

        assertTrue(store.consume(record, NOW).toCompletableFuture().join());
        assertFalse(store.consume(record, NOW).toCompletableFuture().join());
    }

    @Test
    void rejectsConflictingRequestWhileTheFirstIdempotentOperationIsPending() {
        IdempotencyStore store = IdempotencyStore.inMemory(Clock.fixed(NOW, ZoneOffset.UTC));
        CompletableFuture<ServiceResponse<String>> operation = new CompletableFuture<>();
        IdempotencyInput first = new IdempotencyInput(AGENT_DID, "key", "enroll", "sha256:first");
        IdempotencyInput second = new IdempotencyInput(AGENT_DID, "key", "enroll", "sha256:second");

        CompletionStage<IdempotencyResult<String>> pending = store.execute(first, () -> operation);
        IdempotencyResult<String> conflict = store.execute(second, () -> completed(ServiceResponse.success("wrong")))
                .toCompletableFuture()
                .join();
        operation.complete(ServiceResponse.success("first"));

        assertEquals(IdempotencyResult.State.CONFLICT, conflict.state());
        assertEquals("first", pending.toCompletableFuture().join().response().body());
    }

    @Test
    void appliesLifecycleSaveAfterAnInFlightEnrollmentCreation() {
        EnrollmentStore store = EnrollmentStore.inMemory();
        CompletableFuture<EnrollmentRecord> creation = new CompletableFuture<>();
        CompletionStage<EnrollmentSelection> selected = store.findOrCreate(AGENT_DID, () -> creation);
        EnrollmentRecord active = EnrollmentRecord.builder(AGENT_DID, "enrollment", AgentStatus.ACTIVE, NOW)
                .build();
        EnrollmentRecord suspended = EnrollmentRecord.builder(AGENT_DID, "enrollment", AgentStatus.SUSPENDED, NOW)
                .since(NOW.plusSeconds(1))
                .updatedAt(NOW.plusSeconds(1))
                .build();

        CompletionStage<EnrollmentRecord> saved = store.save(suspended);
        creation.complete(active);

        assertEquals(
                AgentStatus.ACTIVE,
                selected.toCompletableFuture().join().record().status());
        assertEquals(AgentStatus.SUSPENDED, saved.toCompletableFuture().join().status());
        assertEquals(
                AgentStatus.SUSPENDED,
                store.find(AGENT_DID).toCompletableFuture().join().orElseThrow().status());
    }

    @Test
    void canonicalizesUnknownClaimObjectMembersForIdempotency() {
        AepService service =
                serviceBuilder(document(false), EnrollmentPolicy.active()).build();
        Map<String, Object> firstOrder = new LinkedHashMap<>();
        firstOrder.put("b", "second");
        firstOrder.put("a", "first");
        Map<String, Object> secondOrder = new LinkedHashMap<>();
        secondOrder.put("a", "first");
        secondOrder.put("b", "second");
        EnrollRequest first = new EnrollRequest(
                AGENT_DID,
                ClaimValues.builder()
                        .contactEmail("agent@example.com")
                        .additional("example.profile", firstOrder)
                        .build(),
                null);
        EnrollRequest second = new EnrollRequest(
                AGENT_DID,
                ClaimValues.builder()
                        .contactEmail("agent@example.com")
                        .additional("example.profile", secondOrder)
                        .build(),
                null);

        ServiceResponse<?> created = service.enroll(first, idempotent("canonical-1", "canonical-key"))
                .toCompletableFuture()
                .join();
        ServiceResponse<?> replay = service.enroll(second, idempotent("canonical-2", "canonical-key"))
                .toCompletableFuture()
                .join();

        assertEquals(200, created.status());
        assertEquals(created, replay);
    }

    @Test
    void rejectsAnUnadvertisedBearerMethod() {
        AepService service = serviceBuilder(documentWithJwtAuthentication(), EnrollmentPolicy.active())
                .build();
        ProtectedResourceResult result = service.authenticate(new ProtectedResourceRequest(
                        Map.of("Authorization", List.of("Bearer credential")),
                        "GET",
                        URI.create("https://service.example/orders/1")))
                .toCompletableFuture()
                .join();

        assertEquals(
                "unsupported_authentication_method", result.response().problem().code());
    }

    @Test
    void validatesServiceConfiguration() {
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> serviceBuilder(document(true), EnrollmentPolicy.active()).build());
        assertTrue(exception.getMessage().contains("Grant Type handlers"));
    }

    @Test
    void verifiesSignaturesWithTheStandardKeyResolverBoundary() throws JOSEException {
        JWK key = new ECKeyGenerator(Curve.P_256).generate();
        ClientAssertionClaims claims = new ClientAssertionClaims(
                AGENT_DID,
                AGENT_DID,
                "did:web:service.example",
                foundation.aep.core.AssertionOperation.ENROLL,
                NOW.minusSeconds(1).getEpochSecond(),
                NOW.plusSeconds(60).getEpochSecond(),
                "signed-assertion",
                null);
        String assertion = ClientAssertions.sign(claims, key, AGENT_DID + "#key-1");
        AepService service = AepService.builder(
                        document(false),
                        ClientAssertionVerifier.withKeyResolver(
                                (token, unverified, context) -> completed(key.toPublicJWK())))
                .clock(Clock.fixed(NOW, ZoneOffset.UTC))
                .build();

        ServiceResponse<?> response = service.enroll(
                        requestWithRequiredClaims(), CommandOptions.idempotent(assertion, "signed-key"))
                .toCompletableFuture()
                .join();

        assertEquals(200, response.status());
    }

    private static AepService.Builder serviceBuilder(InspectDocument document, EnrollmentPolicy policy) {
        Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
        return AepService.builder(
                        document,
                        (assertion, context) -> completed(new ClientAssertionClaims(
                                AGENT_DID,
                                AGENT_DID,
                                context.serviceDid(),
                                context.operation(),
                                NOW.minusSeconds(1).getEpochSecond(),
                                NOW.plusSeconds(60).getEpochSecond(),
                                assertion,
                                context.operation() == foundation.aep.core.AssertionOperation.AUTHENTICATE
                                        ? context.resource()
                                        : null)))
                .clock(clock)
                .enrollmentPolicy(policy)
                .identifierSupplier(() -> "enrollment-1");
    }

    private static EnrollRequest requestWithRequiredClaims() {
        return new EnrollRequest(
                AGENT_DID,
                ClaimValues.builder().contactEmail("agent@example.com").build(),
                null);
    }

    private static CommandOptions idempotent(String assertion, String key) {
        return CommandOptions.idempotent(assertion, key);
    }

    private static void enroll(AepService service) {
        ServiceResponse<?> response = service.enroll(
                        requestWithRequiredClaims(), idempotent("enroll-initial", "enroll-key"))
                .toCompletableFuture()
                .join();
        assertEquals(200, response.status());
    }

    private static InspectDocument document(boolean grants) {
        List<String> commands = grants
                ? List.of("enroll", "grant", "inspect", "revoke", "status")
                : List.of("enroll", "inspect", "status");
        return InspectDocument.builder()
                .version(Aep.VERSION)
                .authentication(grants ? new InspectDocument.Authentication(List.of("api-key")) : null)
                .bindings(new InspectDocument.Bindings(List.of("http")))
                .claims(new InspectDocument.Claims(List.of("contact.email"), List.of(), List.of()))
                .commands(new InspectDocument.Commands(
                        commands,
                        grants ? List.of("api-key") : List.of(),
                        grants ? Map.of("api-key", new InspectDocument.GrantTypeConfig("true")) : Map.of()))
                .core(new InspectDocument.Core(Aep.REQUIRED_SIGNING_ALGORITHMS))
                .http(new InspectDocument.Http("/aep", null))
                .identity(new InspectDocument.Identity(List.of("did:web")))
                .service(new InspectDocument.Service("did:web:service.example"))
                .build();
    }

    private static InspectDocument documentWithGrantTypes(String... grantTypes) {
        List<String> values = List.of(grantTypes);
        Map<String, InspectDocument.GrantTypeConfig> config = new LinkedHashMap<>();
        values.forEach(value -> config.put(value, new InspectDocument.GrantTypeConfig("true")));
        return InspectDocument.builder()
                .version(Aep.VERSION)
                .authentication(new InspectDocument.Authentication(values))
                .bindings(new InspectDocument.Bindings(List.of("http")))
                .claims(new InspectDocument.Claims(List.of("contact.email"), List.of(), List.of()))
                .commands(new InspectDocument.Commands(
                        List.of("enroll", "grant", "inspect", "revoke", "status"), values, config))
                .core(new InspectDocument.Core(Aep.REQUIRED_SIGNING_ALGORITHMS))
                .http(new InspectDocument.Http("/aep", null))
                .identity(new InspectDocument.Identity(List.of("did:web")))
                .service(new InspectDocument.Service("did:web:service.example"))
                .build();
    }

    private static InspectDocument documentWithJwtAuthentication() {
        InspectDocument base = document(false);
        return InspectDocument.builder()
                .version(base.version())
                .authentication(new InspectDocument.Authentication(List.of(Aep.AUTHENTICATION_METHOD_JWT)))
                .bindings(base.bindings())
                .claims(base.claims())
                .commands(base.commands())
                .core(base.core())
                .http(base.http())
                .identity(base.identity())
                .service(base.service())
                .build();
    }

    private static <T> CompletionStage<T> completed(T value) {
        return CompletableFuture.completedFuture(value);
    }

    private static final class RecordingGrantHandler implements GrantTypeHandler {
        private final AtomicInteger revocations = new AtomicInteger();

        @Override
        public CompletionStage<GrantResult> grant(GrantRequest request, GrantContext context) {
            return completed(
                    new GrantResult("credential-1", Map.of("credential_id", "credential-1", "api_key", "secret")));
        }

        @Override
        public CompletionStage<Void> revoke(RevokeRequest request, RevokeContext context) {
            revocations.incrementAndGet();
            return completed(null);
        }
    }

    private static final class EmptyAuthenticator implements CredentialAuthenticator {
        @Override
        public CompletionStage<Boolean> hasPresentation(CredentialAuthenticationInput input) {
            return completed(false);
        }

        @Override
        public CompletionStage<Optional<AuthenticatedPrincipal>> authenticate(CredentialAuthenticationInput input) {
            return completed(Optional.empty());
        }
    }
}
