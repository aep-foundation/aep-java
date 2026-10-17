package foundation.aep.service;

import static foundation.aep.service.ServiceFixtures.AGENT_DID;
import static foundation.aep.service.ServiceFixtures.API_KEY_HEADER;
import static foundation.aep.service.ServiceFixtures.AUTHORIZATION;
import static foundation.aep.service.ServiceFixtures.CLOCK;
import static foundation.aep.service.ServiceFixtures.NOW;
import static foundation.aep.service.ServiceFixtures.SERVICE_DID;
import static foundation.aep.service.ServiceFixtures.authenticate;
import static foundation.aep.service.ServiceFixtures.completed;
import static foundation.aep.service.ServiceFixtures.config;
import static foundation.aep.service.ServiceFixtures.document;
import static foundation.aep.service.ServiceFixtures.enroll;
import static foundation.aep.service.ServiceFixtures.grant;
import static foundation.aep.service.ServiceFixtures.serviceBuilder;
import static foundation.aep.service.ServiceFixtures.storedCredentialService;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import foundation.aep.core.Aep;
import foundation.aep.core.AgentStatus;
import foundation.aep.core.ClaimValues;
import foundation.aep.core.ClientAssertionClaims;
import foundation.aep.core.EnrollRequest;
import foundation.aep.core.GrantRequest;
import foundation.aep.core.GrantResponses;
import foundation.aep.core.InspectDocument;
import foundation.aep.core.RevokeRequest;
import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CompletionStage;
import org.junit.jupiter.api.Test;

/** Field-by-field validation of the AEP Service surface. */
final class ServiceValidationTest {
    private static final String API_KEY = Aep.GRANT_TYPE_API_KEY;
    private static final String EXPIRY = "2026-09-01T12:10:00Z";
    private static final String CREDENTIAL_ID = "api-1";
    private static final String NOT_RECOGNIZED = "not_recognized";

    @Test
    void acceptsAnEchoedIdempotencyKeyInTheEnrollBody() {
        AepService service =
                serviceBuilder(document(List.of(), Map.of(), List.of())).build();

        assertEquals(
                200,
                status(service.enroll(
                        new EnrollRequest(AGENT_DID, null, "key-1"), CommandOptions.idempotent("a1", "key-1"))));
        assertEquals(
                400,
                status(service.enroll(
                        new EnrollRequest(AGENT_DID, null, "other"), CommandOptions.idempotent("a2", "key-2"))));
    }

    @Test
    void treatsAnAbsentClaimsAdvertisementAsNoRequirements() {
        InspectDocument document = InspectDocument.builder()
                .version(Aep.VERSION)
                .bindings(new InspectDocument.Bindings(List.of("http")))
                .commands(new InspectDocument.Commands(List.of("enroll", "inspect", "status"), List.of(), Map.of()))
                .core(new InspectDocument.Core(Aep.REQUIRED_SIGNING_ALGORITHMS))
                .http(new InspectDocument.Http("/aep", null))
                .identity(new InspectDocument.Identity(List.of("did:web")))
                .service(new InspectDocument.Service(SERVICE_DID))
                .build();
        AepService service = serviceBuilder(document).build();

        assertEquals(
                200,
                status(service.enroll(new EnrollRequest(AGENT_DID, null, null), CommandOptions.idempotent("a", "k"))),
                "a Service advertising no claims requires none");
    }

    @Test
    void reportsEveryRequiredClaimTheRequestOmits() {
        InspectDocument document = InspectDocument.builder()
                .version(Aep.VERSION)
                .bindings(new InspectDocument.Bindings(List.of("http")))
                .claims(new InspectDocument.Claims(List.of("contact.email", "person.username"), List.of(), List.of()))
                .commands(new InspectDocument.Commands(List.of("enroll", "inspect", "status"), List.of(), Map.of()))
                .core(new InspectDocument.Core(Aep.REQUIRED_SIGNING_ALGORITHMS))
                .http(new InspectDocument.Http("/aep", null))
                .identity(new InspectDocument.Identity(List.of("did:web")))
                .service(new InspectDocument.Service(SERVICE_DID))
                .build();
        AepService service = serviceBuilder(document).build();

        var response = service.enroll(
                        new EnrollRequest(
                                AGENT_DID,
                                ClaimValues.builder()
                                        .contactEmail("agent@example.com")
                                        .build(),
                                null),
                        CommandOptions.idempotent("a", "k"))
                .toCompletableFuture()
                .join();

        assertEquals(422, response.status());
        assertEquals(List.of("person.username"), response.problem().requirementsPending());
    }

    @Test
    void refusesPerCredentialRevokeWhenNoConfigurationIsAdvertised() {
        AepService service = serviceBuilder(document(List.of(API_KEY), Map.of()))
                .grantType(new GrantTypeDefinition(API_KEY, handler()))
                .credentialAuthenticator(API_KEY, handler())
                .build();
        enroll(service);

        assertEquals(
                400,
                status(service.revoke(
                        new RevokeRequest(API_KEY, CREDENTIAL_ID, null), CommandOptions.idempotent("r", "r-key"))));
        assertEquals(
                200,
                status(service.revoke(
                        new RevokeRequest(null, null, "true"), CommandOptions.idempotent("r2", "r2-key"))),
                "an all-Grant-Types revoke needs no per-credential configuration");
    }

    @Test
    void refusesAssertionsWithNoCredentialToVerify() {
        AepService service =
                serviceBuilder(document(List.of(), Map.of(), List.of())).build();

        assertEquals(401, status(service.status(CommandOptions.authenticated(null))));
        assertEquals(401, status(service.status(CommandOptions.authenticated(""))));
    }

    @Test
    void refusesClaimsOutsideTheirValidityWindow() {
        assertEquals(401, status(timed(NOW.plusSeconds(120), NOW.plusSeconds(180))), "issued in the future");
        assertEquals(401, status(timed(NOW.minusSeconds(180), NOW.minusSeconds(120))), "already expired");
        assertEquals(200, status(timed(NOW.minusSeconds(1), NOW.plusSeconds(60))));
    }

    @Test
    void refusesClaimsBoundToAnotherResource() {
        AepService service = serviceBuilder(document(List.of(), Map.of(), List.of(Aep.AUTHENTICATION_METHOD_JWT)))
                .build();
        enroll(service);

        assertTrue(authenticate(service, Map.of(AUTHORIZATION, List.of("AEP fresh")))
                .authenticated());

        AepService misbinding = AepService.builder(
                        document(List.of(), Map.of(), List.of(Aep.AUTHENTICATION_METHOD_JWT)),
                        (assertion, context) -> completed(new ClientAssertionClaims(
                                AGENT_DID,
                                AGENT_DID,
                                context.serviceDid(),
                                context.operation(),
                                NOW.minusSeconds(1).getEpochSecond(),
                                NOW.plusSeconds(60).getEpochSecond(),
                                assertion,
                                "https://service.example/elsewhere")))
                .clock(CLOCK)
                .build();
        enroll(misbinding);

        assertFalse(authenticate(misbinding, Map.of(AUTHORIZATION, List.of("AEP a")))
                .authenticated());
    }

    @Test
    void refusesVerifiersThatReturnNoClaimsAtAll() {
        AepService service = AepService.builder(
                        document(List.of(), Map.of(), List.of()), (assertion, context) -> completed(null))
                .clock(CLOCK)
                .build();

        assertEquals(401, status(service.status(CommandOptions.authenticated("a"))));
    }

    @Test
    void walksPastAuthenticationMethodsThatPresentNothing() {
        AepService service = serviceBuilder(document(
                        List.of(API_KEY),
                        Map.of(API_KEY, config(List.of(API_KEY_HEADER))),
                        List.of(Aep.AUTHENTICATION_METHOD_JWT, API_KEY)))
                .storedCredentialGrantType(StoredCredentialGrantTypes.apiKey(
                        config(List.of(API_KEY_HEADER)),
                        (request, context) -> completed(apiKey()),
                        ServiceCredentialStore.inMemory()))
                .build();
        enroll(service);
        grant(service, API_KEY);

        assertEquals(
                CREDENTIAL_ID,
                authenticate(service, Map.of(API_KEY_HEADER, List.of("api-secret")))
                        .principal()
                        .credentialId(),
                "aep-jwt is skipped and the api-key method answers");
        assertEquals("authentication_required", rejected(service, Map.of("X-Other", List.of("api-secret"))));
    }

    @Test
    void rejectsPrincipalsThatDoNotDescribeTheirOwnCredential() {
        assertThrows(CompletionException.class, () -> principal(null, API_KEY, API_KEY));
        assertThrows(CompletionException.class, () -> principal(" ", API_KEY, API_KEY));
        assertThrows(CompletionException.class, () -> principal(AGENT_DID, "other", API_KEY));
        assertThrows(CompletionException.class, () -> principal(AGENT_DID, API_KEY, "other"));
    }

    @Test
    void requiresEveryAdvertisedMethodToHaveBothHandlers() {
        assertThrows(
                IllegalArgumentException.class,
                () -> serviceBuilder(document(List.of(API_KEY), Map.of(API_KEY, config(List.of())), List.of(API_KEY)))
                        .grantType(new GrantTypeDefinition(API_KEY, handler()))
                        .build(),
                "a Grant Type without an authenticator cannot authenticate");
        assertThrows(
                IllegalArgumentException.class,
                () -> serviceBuilder(document(List.of(), Map.of(), List.of()))
                        .grantType(new GrantTypeDefinition(API_KEY, handler()))
                        .build(),
                "an unadvertised Grant Type has no handler slot");
    }

    @Test
    void recognizesOnlyAdvertisedIdentityMethods() {
        AepService service = AepService.builder(
                        document(List.of(), Map.of(), List.of()),
                        (assertion, context) -> completed(new ClientAssertionClaims(
                                "did:example:1",
                                "did:example:1",
                                context.serviceDid(),
                                context.operation(),
                                NOW.minusSeconds(1).getEpochSecond(),
                                NOW.plusSeconds(60).getEpochSecond(),
                                assertion,
                                null)))
                .clock(CLOCK)
                .build();

        assertEquals(401, status(service.status(CommandOptions.authenticated("a"))));
    }

    @Test
    void foldsEveryOptionalRequestMemberIntoTheFingerprint() {
        AepService service = storedCredentialService(ServiceCredentialStore.inMemory());
        enroll(service);

        assertEquals(
                200,
                status(service.grant(
                        new GrantRequest(Aep.GRANT_TYPE_OAUTH_BEARER, "laptop", List.of("read"), "opaque"),
                        CommandOptions.idempotent("g1", "g-key"))));
        assertEquals(
                409,
                status(service.grant(
                        new GrantRequest(Aep.GRANT_TYPE_OAUTH_BEARER, "phone", List.of("read"), "opaque"),
                        CommandOptions.idempotent("g2", "g-key"))),
                "the label is material input");
        assertEquals(
                200,
                status(service.revoke(
                        new RevokeRequest(null, null, "true"), CommandOptions.idempotent("r1", "r-key"))));
        assertEquals(
                409,
                status(service.revoke(
                        new RevokeRequest(Aep.GRANT_TYPE_OAUTH_BEARER, null, null),
                        CommandOptions.idempotent("r2", "r-key"))));
    }

    @Test
    void refusesGeneratedIdentifiersItCannotUse() {
        assertThrows(CompletionException.class, () -> generated(null));
        assertThrows(CompletionException.class, () -> generated(" "));
    }

    @Test
    void appliesLoopbackRulesToEveryConfiguredUri() {
        var strict = serviceBuilder(document(List.of(), Map.of(), List.of()));

        assertThrows(
                IllegalArgumentException.class,
                () -> strict.inspectUri(URI.create("https://user@service.example/x"))
                        .build());
        assertThrows(
                IllegalArgumentException.class,
                () -> strict.inspectUri(URI.create("https://service.example/x#f"))
                        .build());
        assertThrows(
                IllegalArgumentException.class,
                () -> strict.inspectUri(URI.create("/relative")).build());
        assertEquals(
                "http://localhost:9000/.well-known/aep",
                serviceBuilder(document(List.of(), Map.of(), List.of()))
                        .allowInsecureLoopback(true)
                        .inspectUri(URI.create("http://localhost:9000/.well-known/aep"))
                        .build()
                        .authenticate(new ProtectedResourceRequest(
                                Map.of(), "GET", URI.create("https://service.example/private")))
                        .toCompletableFuture()
                        .join()
                        .response()
                        .headers()
                        .get("WWW-Authenticate")
                        .get(0)
                        .replaceAll(".*inspect=\"([^\"]+)\".*", "$1"));
    }

    @Test
    void normalizesOptionalDecisionAndPrincipalMembers() {
        EnrollmentDecision decision = new EnrollmentDecision(null, false, null, null);

        assertEquals(AgentStatus.ACTIVE, decision.status());
        assertEquals(List.of(), decision.verificationPending());
        assertEquals(List.of(), decision.requirementsPending());
        assertEquals(AgentStatus.ACTIVE, EnrollmentDecision.active().status());
        assertThrows(
                IllegalArgumentException.class,
                () -> new EnrollmentDecision(AgentStatus.SUSPENDED, false, List.of(), List.of()));
        assertEquals(
                List.of(),
                new AuthenticatedPrincipal(AGENT_DID, API_KEY, null, null, null, AuthenticatedPrincipal.Kind.AEP_JWT)
                        .scopes());
        assertEquals(List.of(), new ServiceCredentialMatch(AGENT_DID, CREDENTIAL_ID, NOW, API_KEY, null).scopes());
    }

    @Test
    void guardsHttpResponseInvariants() {
        assertThrows(
                IllegalArgumentException.class, () -> new AepHttpResponse(99, Aep.MEDIA_TYPE, Map.of(), new byte[0]));
        assertThrows(
                IllegalArgumentException.class, () -> new AepHttpResponse(600, Aep.MEDIA_TYPE, Map.of(), new byte[0]));
        assertThrows(NullPointerException.class, () -> new AepHttpResponse(200, null, Map.of(), new byte[0]));
        assertEquals(0, new AepHttpResponse(200, Aep.MEDIA_TYPE, null, null).body().length);
        assertEquals(Map.of(), new AepHttpResponse(200, Aep.MEDIA_TYPE, null, null).headers());
    }

    @Test
    void keepsAnIssuedCredentialOutOfAnotherAgentsReach() {
        ServiceCredentialStore store = ServiceCredentialStore.inMemory();
        AepService service = storedCredentialService(store);
        enroll(service);
        grant(service, API_KEY);

        store.revokeGrantType("did:web:someone.example", API_KEY, NOW)
                .toCompletableFuture()
                .join();

        assertTrue(authenticate(service, Map.of(API_KEY_HEADER, List.of("api-secret")))
                .authenticated());
    }

    @Test
    void refusesExpiredCredentialsWithoutForgettingThem() {
        ServiceCredentialStore store = ServiceCredentialStore.inMemory();
        AepService service = serviceBuilder(
                        document(List.of(API_KEY), Map.of(API_KEY, config(List.of(API_KEY_HEADER)))))
                .clock(java.time.Clock.fixed(NOW.plusSeconds(3600), java.time.ZoneOffset.UTC))
                .storedCredentialGrantType(StoredCredentialGrantTypes.apiKey(
                        config(List.of(API_KEY_HEADER)), (request, context) -> completed(apiKey()), store))
                .build();
        store.save(new ServiceCredentialRecord(AGENT_DID, NOW, apiKey(), CREDENTIAL_ID, Instant.parse(EXPIRY), API_KEY))
                .toCompletableFuture()
                .join();
        enroll(service);

        assertEquals(
                NOT_RECOGNIZED,
                rejected(service, Map.of(API_KEY_HEADER, List.of("api-secret"))),
                "the header is still known, so this is a bad credential rather than none");
    }

    @Test
    void walksEveryAuthenticationMethodBeforeReportingAnAbsentCredential() {
        AepService service = serviceBuilder(document(
                        List.of(API_KEY),
                        Map.of(API_KEY, config(List.of(API_KEY_HEADER))),
                        List.of(Aep.AUTHENTICATION_METHOD_JWT, API_KEY)))
                .grantType(new GrantTypeDefinition(API_KEY, handler()))
                .credentialAuthenticator(API_KEY, new CredentialAuthenticator() {
                    @Override
                    public CompletionStage<Boolean> hasPresentation(CredentialAuthenticationInput input) {
                        return completed(!input.headers()
                                .getOrDefault(API_KEY_HEADER, List.of())
                                .isEmpty());
                    }

                    @Override
                    public CompletionStage<Optional<AuthenticatedPrincipal>> authenticate(
                            CredentialAuthenticationInput input) {
                        return completed(Optional.empty());
                    }
                })
                .build();
        enroll(service);

        assertEquals(
                "authentication_required",
                rejected(service, Map.of()),
                "aep-jwt is skipped and nothing else presented anything");
        assertEquals(
                NOT_RECOGNIZED,
                rejected(service, Map.of(API_KEY_HEADER, List.of("wrong"))),
                "a presentation that no authenticator accepts is a bad credential");
    }

    @Test
    void refusesSessionCredentialsForAgentsWithNoEnrollmentAtAll() {
        ServiceCredentialStore store = ServiceCredentialStore.inMemory();
        AepService issuing = storedCredentialService(store);
        enroll(issuing);
        grant(issuing, API_KEY);
        AepService fresh = storedCredentialService(store, EnrollmentStore.inMemory());

        assertEquals(NOT_RECOGNIZED, rejected(fresh, Map.of(API_KEY_HEADER, List.of("api-secret"))));
    }

    @Test
    void readsIdentityMethodsOnlyFromWellFormedSubjects() {
        assertEquals(401, status(subject("notadid")));
        assertEquals(401, status(subject("did:web")));
        assertEquals(401, status(subject("web:example:1")));
    }

    @Test
    void refusesInspectUrisThatAreNotAbsoluteOrigins() {
        var builder = serviceBuilder(document(List.of(), Map.of(), List.of())).allowInsecureLoopback(true);

        assertThrows(
                IllegalArgumentException.class,
                () -> builder.inspectUri(URI.create("https:/.well-known/aep")).build(),
                "an authority is required");
        assertThrows(
                IllegalArgumentException.class,
                () -> builder.inspectUri(URI.create("http://user@127.0.0.1/x")).build());
        assertThrows(
                IllegalArgumentException.class,
                () -> builder.inspectUri(URI.create("http://127.0.0.1/x#f")).build());
        assertThrows(
                IllegalArgumentException.class,
                () -> builder.inspectUri(URI.create("http://example.com/x")).build(),
                "a non-loopback host still needs HTTPS");
    }

    @Test
    void refusesMoreThanOneDedicatedAuthorizationField() {
        AepService service = storedCredentialService(ServiceCredentialStore.inMemory());
        enroll(service);
        grant(service, Aep.GRANT_TYPE_OAUTH_BEARER);

        assertEquals(
                NOT_RECOGNIZED,
                rejected(service, Map.of(Aep.AUTHORIZATION_HEADER, List.of("Bearer oauth-secret", "Bearer other"))));
    }

    @Test
    void unwrapsNestedCompletionFailuresFromIdempotentOperations() {
        AepService service = serviceBuilder(document(List.of(API_KEY), Map.of(API_KEY, config(List.of()))))
                .grantType(new GrantTypeDefinition(API_KEY, new GrantTypeHandler() {
                    @Override
                    public CompletionStage<GrantResult> grant(GrantRequest request, GrantContext context) {
                        return java.util.concurrent.CompletableFuture.failedFuture(new CompletionException(
                                new java.util.concurrent.ExecutionException(new IllegalStateException("boom"))));
                    }

                    @Override
                    public CompletionStage<Void> revoke(RevokeRequest request, RevokeContext context) {
                        return completed(null);
                    }
                }))
                .credentialAuthenticator(API_KEY, handler())
                .build();
        enroll(service);

        CompletionException failure = assertThrows(
                CompletionException.class,
                () -> service.grant(new GrantRequest(API_KEY, List.of()), CommandOptions.idempotent("g", "g-key"))
                        .toCompletableFuture()
                        .join());

        assertTrue(failure.getCause() instanceof IllegalStateException);
    }

    @Test
    void storesBasicCredentialsUnderTheAuthorizationSlot() {
        ServiceCredentialStore store = ServiceCredentialStore.inMemory();
        AepService service = storedCredentialService(store);
        enroll(service);
        grant(service, Aep.GRANT_TYPE_BASIC);

        assertTrue(authenticate(service, Map.of(AUTHORIZATION, List.of("Basic " + ServiceFixtures.basicCredentials())))
                .authenticated());
        assertEquals(
                "authentication_required",
                rejected(service, Map.of("X-Unrelated", List.of("Basic " + ServiceFixtures.basicCredentials()))));
    }

    @Test
    void refusesCredentialRecordsThatDisagreeWithTheirResponse() {
        ServiceCredentialStore store = ServiceCredentialStore.inMemory();

        assertThrows(
                CompletionException.class,
                () -> store.save(new ServiceCredentialRecord(
                                AGENT_DID,
                                NOW,
                                apiKey(),
                                CREDENTIAL_ID,
                                Instant.parse("2026-09-01T12:20:00Z"),
                                API_KEY))
                        .toCompletableFuture()
                        .join(),
                "the record expiry has to equal the credential expiry");
        assertThrows(
                CompletionException.class,
                () -> store.save(new ServiceCredentialRecord(
                                " ", NOW, apiKey(), CREDENTIAL_ID, Instant.parse(EXPIRY), API_KEY))
                        .toCompletableFuture()
                        .join());
    }

    @Test
    void acceptsEveryJsonShapeAClaimValueMayTake() {
        ClaimValueLimits limits = new ClaimValueLimits(65_536, 32, 8, 64);

        assertTrue(limits.accepts(ClaimValues.builder()
                .additional("flag", true)
                .additional("count", 3)
                .additional("absent", null)
                .additional("list", List.of("a", "b"))
                .build()));
        assertFalse(
                new ClaimValueLimits(65_536, 1, 8, 64)
                        .accepts(ClaimValues.builder()
                                .additional("a", "1")
                                .additional("b", "2")
                                .build()),
                "the member budget covers every object in the document");
    }

    private static CompletionStage<? extends ServiceResponse<?>> subject(String value) {
        AepService service = AepService.builder(
                        document(List.of(), Map.of(), List.of()),
                        (assertion, context) -> completed(new ClientAssertionClaims(
                                value,
                                value,
                                context.serviceDid(),
                                context.operation(),
                                NOW.minusSeconds(1).getEpochSecond(),
                                NOW.plusSeconds(60).getEpochSecond(),
                                assertion,
                                null)))
                .clock(CLOCK)
                .build();
        return service.status(CommandOptions.authenticated("a"));
    }

    private static void generated(String identifier) {
        AepService service = serviceBuilder(document(List.of(), Map.of(), List.of()))
                .identifierSupplier(() -> identifier)
                .build();
        service.enroll(new EnrollRequest(AGENT_DID, null, null), CommandOptions.idempotent("a", "k"))
                .toCompletableFuture()
                .join();
    }

    private static void principal(String agentDid, String method, String grantType) {
        AepService service = serviceBuilder(document(List.of(API_KEY), Map.of(API_KEY, config(List.of()))))
                .grantType(new GrantTypeDefinition(API_KEY, handler()))
                .credentialAuthenticator(API_KEY, new CredentialAuthenticator() {
                    @Override
                    public CompletionStage<Boolean> hasPresentation(CredentialAuthenticationInput input) {
                        return completed(true);
                    }

                    @Override
                    public CompletionStage<Optional<AuthenticatedPrincipal>> authenticate(
                            CredentialAuthenticationInput input) {
                        return completed(Optional.of(new AuthenticatedPrincipal(
                                agentDid,
                                method,
                                CREDENTIAL_ID,
                                grantType,
                                List.of(),
                                AuthenticatedPrincipal.Kind.SESSION_CREDENTIAL)));
                    }
                })
                .build();
        enroll(service);
        authenticate(service, Map.of(API_KEY_HEADER, List.of("api-secret")));
    }

    private static CompletionStage<? extends ServiceResponse<?>> timed(Instant issuedAt, Instant expiresAt) {
        AepService service = AepService.builder(
                        document(List.of(), Map.of(), List.of()),
                        (assertion, context) -> completed(new ClientAssertionClaims(
                                AGENT_DID,
                                AGENT_DID,
                                context.serviceDid(),
                                context.operation(),
                                issuedAt.getEpochSecond(),
                                expiresAt.getEpochSecond(),
                                assertion,
                                null)))
                .clock(CLOCK)
                .clockSkew(Duration.ofSeconds(30))
                .build();
        enroll(service);
        return service.status(CommandOptions.authenticated("status"));
    }

    private static GrantResponses.ApiKey apiKey() {
        return new GrantResponses.ApiKey("api-secret", CREDENTIAL_ID, EXPIRY, API_KEY_HEADER, List.of("read"));
    }

    private static int status(CompletionStage<? extends ServiceResponse<?>> stage) {
        return stage.toCompletableFuture().join().status();
    }

    private static String rejected(AepService service, Map<String, List<String>> headers) {
        ProtectedResourceResult result = authenticate(service, headers);
        assertFalse(result.authenticated(), "expected a rejection");
        return result.response().problem().code();
    }

    private static Handler handler() {
        return new Handler();
    }

    private static final class Handler implements GrantTypeHandler, CredentialAuthenticator {
        @Override
        public CompletionStage<GrantResult> grant(GrantRequest request, GrantContext context) {
            return completed(new GrantResult(CREDENTIAL_ID, Map.of("credential_id", CREDENTIAL_ID)));
        }

        @Override
        public CompletionStage<Void> revoke(RevokeRequest request, RevokeContext context) {
            return completed(null);
        }

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
