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
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import foundation.aep.core.Aep;
import foundation.aep.core.AgentStatus;
import foundation.aep.core.AssertionOperation;
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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CompletionStage;
import org.junit.jupiter.api.Test;

/** Exercises the refusal, accessor, and store paths of the AEP Service module. */
final class ServiceCoverageTest {
    private static final String INVALID_REQUEST = "invalid_request";
    private static final String NOT_RECOGNIZED = "not_recognized";
    private static final String ENROLL_KEY = "enroll-key";
    private static final String GRANT_KEY = "grant-key";
    private static final String API_KEY = Aep.GRANT_TYPE_API_KEY;
    private static final String EXPIRY = "2026-09-01T12:10:00Z";

    @Test
    void refusesCommandsWithoutAKeyOrWithAMismatchedBody() {
        AepService service = apiKeyService();

        // Each command needs its own assertion: a client assertion is single-use, so reusing one
        // would be refused as a replay before the request shape is ever examined.
        assertEquals(400, code(service.enroll(enrollRequest(), CommandOptions.authenticated("a1"))));
        assertEquals(400, code(service.enroll(null, CommandOptions.idempotent("a2", "k1"))));
        assertEquals(
                400,
                code(service.enroll(
                        new EnrollRequest("did:web:other.example", null, null),
                        CommandOptions.idempotent("a3", "k2"))));
        assertEquals(
                400,
                code(service.enroll(
                        new EnrollRequest(AGENT_DID, null, "other"), CommandOptions.idempotent("a4", "k3"))));
        assertEquals(
                400, code(service.enroll(new EnrollRequest(" ", null, null), CommandOptions.idempotent("a5", "k4"))));
        assertEquals(400, code(service.grant(null, CommandOptions.idempotent("a6", "k5"))));
        assertEquals(400, code(service.grant(grantRequest(), CommandOptions.authenticated("a7"))));
        assertEquals(400, code(service.revoke(null, CommandOptions.idempotent("a8", "k6"))));
        assertEquals(
                400, code(service.revoke(new RevokeRequest(API_KEY, null, null), CommandOptions.authenticated("a9"))));
        assertEquals(401, code(service.enroll(enrollRequest(), CommandOptions.idempotent(" ", "k7"))));
        assertEquals(401, code(service.status(null)));
        assertEquals(401, code(service.grant(grantRequest(), null)));
    }

    @Test
    void reportsStatusForAnEnrolledAgent() {
        AepService service = apiKeyService();
        enroll(service);

        var response = service.status(CommandOptions.authenticated("status"))
                .toCompletableFuture()
                .join();
        var body = (foundation.aep.core.StatusResponse) response.body();

        assertEquals(200, response.status());
        assertEquals(AgentStatus.ACTIVE, body.status());
        assertEquals("2026-09-01T12:00:00Z", body.since());
        assertEquals(null, body.ownerActionRequired());
        assertEquals(401, code(freshService().status(CommandOptions.authenticated("status"))));
    }

    @Test
    void reportsPendingLifecycleDetailOnStatus() {
        AepService service = serviceBuilder(document(List.of(), Map.of(), List.of()))
                .enrollmentPolicy((request, now) -> completed(new EnrollmentDecision(
                        AgentStatus.PENDING, true, List.of("contact.email"), List.of("person.username"))))
                .build();
        enroll(service);

        var body = (foundation.aep.core.StatusResponse) service.status(CommandOptions.authenticated("status"))
                .toCompletableFuture()
                .join()
                .body();

        assertEquals("true", body.ownerActionRequired());
        assertEquals(List.of("contact.email"), body.verificationPending());
        assertEquals(List.of("person.username"), body.requirementsPending());
    }

    @Test
    void refusesUnsupportedGrantTypesOnBothCommands() {
        AepService service = apiKeyService();
        enroll(service);

        assertEquals(
                400,
                code(service.grant(new GrantRequest("other", List.of()), CommandOptions.idempotent("g1", GRANT_KEY))));
        assertEquals(
                400,
                code(service.revoke(new RevokeRequest("other", null, null), CommandOptions.idempotent("r1", "r-key"))));
        assertEquals(
                200,
                code(service.revoke(
                        new RevokeRequest(API_KEY, "credential-1", null), CommandOptions.idempotent("r2", "r2-key"))),
                "this Service advertises per-credential revoke");

        AepService withoutTargetedRevoke = serviceBuilder(
                        document(List.of(API_KEY), Map.of(API_KEY, new InspectDocument.GrantTypeConfig("false"))))
                .grantType(new GrantTypeDefinition(API_KEY, handler()))
                .credentialAuthenticator(API_KEY, handler())
                .build();
        enroll(withoutTargetedRevoke);
        assertEquals(
                400,
                code(withoutTargetedRevoke.revoke(
                        new RevokeRequest(API_KEY, "credential-1", null), CommandOptions.idempotent("r3", "r3-key"))),
                "per-credential revoke is refused when the Service does not advertise it");
    }

    @Test
    void refusesGrantAndRevokeForAnAgentThatNeverEnrolled() {
        AepService service = apiKeyService();

        assertEquals(401, code(service.grant(grantRequest(), CommandOptions.idempotent("g1", GRANT_KEY))));
        assertEquals(
                401,
                code(service.revoke(new RevokeRequest(API_KEY, null, null), CommandOptions.idempotent("r1", "r-key"))));
    }

    @Test
    void reportsUnmetClaimRequirementsAndOversizedClaimValues() {
        InspectDocument document = InspectDocument.builder()
                .version(Aep.VERSION)
                .bindings(new InspectDocument.Bindings(List.of("http")))
                .claims(new InspectDocument.Claims(List.of("contact.email"), List.of(), List.of()))
                .commands(new InspectDocument.Commands(List.of("enroll", "inspect", "status"), List.of(), Map.of()))
                .core(new InspectDocument.Core(Aep.REQUIRED_SIGNING_ALGORITHMS))
                .http(new InspectDocument.Http("/aep", null))
                .identity(new InspectDocument.Identity(List.of("did:web")))
                .service(new InspectDocument.Service(SERVICE_DID))
                .build();
        AepService service = serviceBuilder(document).build();
        AepService limited = serviceBuilder(document)
                .claimValueLimits(new ClaimValueLimits(64, 1, 1, 4))
                .build();

        var missing = service.enroll(new EnrollRequest(AGENT_DID, null, null), CommandOptions.idempotent("e", "k"))
                .toCompletableFuture()
                .join();

        assertEquals(422, missing.status());
        assertEquals(List.of("contact.email"), missing.problem().requirementsPending());
        assertEquals(
                422,
                code(limited.enroll(
                        new EnrollRequest(
                                AGENT_DID,
                                ClaimValues.builder()
                                        .contactEmail("a-very-long-address@example.com")
                                        .build(),
                                null),
                        CommandOptions.idempotent("e", "k2"))));
    }

    @Test
    void foldsEveryCanonicalClaimIntoTheIdempotencyFingerprint() {
        AepService service =
                serviceBuilder(document(List.of(), Map.of(), List.of())).build();
        Map<String, Object> nested = new LinkedHashMap<>();
        nested.put("list", List.of(1, "two", true));
        ClaimValues first = ClaimValues.builder()
                .contactAddressPrimary(new foundation.aep.core.ContactAddressPrimary(
                        "Springfield", "US", "Ada", "Lovelace", "1 Main St", null, null, "12345", "IL"))
                .contactEmail("agent@example.com")
                .contactMobile("+15550100")
                .personBirthdate("1990-01-01")
                .personFirstName("Ada")
                .personLastName("Lovelace")
                .personUsername("ada")
                .additional("nested", nested)
                .build();

        assertEquals(200, code(service.enroll(new EnrollRequest(AGENT_DID, first, null), key("k1", "a1"))));
        assertEquals(
                200,
                code(service.enroll(new EnrollRequest(AGENT_DID, first, null), key("k1", "a2"))),
                "an exact retry replays the stored result");
        assertEquals(
                409,
                code(service.enroll(
                        new EnrollRequest(
                                AGENT_DID,
                                ClaimValues.builder().personUsername("bo").build(),
                                null),
                        key("k1", "a3"))));
    }

    @Test
    void refusesProtectedResourceUrlsItCannotBind() {
        AepService service = apiKeyService();

        assertThrows(CompletionException.class, () -> resource(service, URI.create("/relative")));
        assertThrows(CompletionException.class, () -> resource(service, URI.create("https://user@svc.example/x")));
        assertThrows(CompletionException.class, () -> resource(service, URI.create("https://svc.example/x#f")));
        assertThrows(CompletionException.class, () -> resource(service, URI.create("http://svc.example/x")));
        assertThrows(CompletionException.class, () -> resource(service, null));
    }

    @Test
    void allowsLoopbackProtectedResourcesOnlyWhenConfigured() {
        AepService loopback = serviceBuilder(document(List.of(), Map.of(), List.of()))
                .allowInsecureLoopback(true)
                .inspectUri(URI.create("http://127.0.0.1:8080/.well-known/aep"))
                .build();

        var rejected = loopback.authenticate(
                        new ProtectedResourceRequest(Map.of(), "GET", URI.create("http://localhost:8080/private")))
                .toCompletableFuture()
                .join();

        assertFalse(rejected.authenticated());
        var ipv6 = loopback.authenticate(
                        new ProtectedResourceRequest(Map.of(), "GET", URI.create("http://[::1]:8080/private")))
                .toCompletableFuture()
                .join();
        assertFalse(ipv6.authenticated());
        assertEquals(401, ipv6.response().status());
        for (String host : List.of("192.0.2.1", "999.999.999.999")) {
            assertThrows(
                    CompletionException.class,
                    () -> loopback.authenticate(new ProtectedResourceRequest(
                                    Map.of(), "GET", URI.create("http://" + host + "/private")))
                            .toCompletableFuture()
                            .join());
        }
        assertTrue(rejected.response()
                .headers()
                .get("WWW-Authenticate")
                .get(0)
                .contains("inspect=\"http://127.0.0.1:8080/.well-known/aep\""));
        assertThrows(
                CompletionException.class,
                () -> loopback.authenticate(new ProtectedResourceRequest(
                                Map.of(), "GET", URI.create("http://example.invalid/private")))
                        .toCompletableFuture()
                        .join());
    }

    @Test
    void refusesAepAssertionsOnResourcesThatDoNotAdvertiseThem() {
        AepService service = apiKeyService();
        enroll(service);

        assertEquals(
                "unsupported_authentication_method",
                rejected(service, Map.of(AUTHORIZATION, List.of("AEP assertion"))));
        assertEquals(
                "unsupported_authentication_method",
                rejected(service, Map.of(AUTHORIZATION, List.of("Bearer token"))),
                "the Service advertises only api-key");
    }

    @Test
    void refusesAnAssertionPresentedAlongsideASessionCredential() {
        AepService service = jwtAndApiKeyService();
        enroll(service);
        grant(service, API_KEY);

        assertEquals(
                NOT_RECOGNIZED,
                rejected(
                        service,
                        Map.of(AUTHORIZATION, List.of("AEP assertion"), API_KEY_HEADER, List.of("api-secret"))));
    }

    @Test
    void authenticatesAepAssertionsAgainstActiveEnrollmentsOnly() {
        EnrollmentStore store = EnrollmentStore.inMemory();
        AepService service = serviceBuilder(document(List.of(), Map.of(), List.of(Aep.AUTHENTICATION_METHOD_JWT)))
                .enrollmentStore(store)
                .build();

        assertEquals(NOT_RECOGNIZED, rejected(service, Map.of(AUTHORIZATION, List.of("AEP assertion-1"))));
        enroll(service);
        var authenticated = authenticate(service, Map.of(AUTHORIZATION, List.of("AEP assertion-2")));
        assertTrue(authenticated.authenticated());
        assertEquals(
                AuthenticatedPrincipal.Kind.AEP_JWT, authenticated.principal().kind());
        assertEquals(Aep.AUTHENTICATION_METHOD_JWT, authenticated.principal().authenticationMethod());

        store.save(EnrollmentRecord.builder(AGENT_DID, "enrollment-1", AgentStatus.SUSPENDED, NOW)
                        .since(NOW)
                        .updatedAt(NOW)
                        .build())
                .toCompletableFuture()
                .join();
        assertEquals(NOT_RECOGNIZED, rejected(service, Map.of(AUTHORIZATION, List.of("AEP assertion-3"))));
    }

    @Test
    void rejectsAssertionsTheVerifierCannotProduce() {
        AepService throwing = AepService.builder(document(List.of(), Map.of(), List.of()), (assertion, context) -> {
                    throw new IllegalStateException("boom");
                })
                .clock(CLOCK)
                .build();
        AepService failing = AepService.builder(
                        document(List.of(), Map.of(), List.of()),
                        (assertion, context) ->
                                java.util.concurrent.CompletableFuture.failedFuture(new IllegalStateException("no")))
                .clock(CLOCK)
                .build();
        AepService overflowing = AepService.builder(
                        document(List.of(), Map.of(), List.of()),
                        (assertion, context) -> completed(new ClientAssertionClaims(
                                AGENT_DID,
                                AGENT_DID,
                                context.serviceDid(),
                                context.operation(),
                                NOW.getEpochSecond(),
                                Long.MAX_VALUE,
                                assertion,
                                null)))
                .clock(CLOCK)
                .build();

        assertEquals(401, code(throwing.status(CommandOptions.authenticated("a"))));
        assertEquals(401, code(failing.status(CommandOptions.authenticated("a"))));
        assertEquals(401, code(overflowing.status(CommandOptions.authenticated("a"))));
    }

    @Test
    void rejectsClaimsThatDoNotBindTheRequestTheyAuthorize() {
        assertEquals(401, code(claiming(AGENT_DID, "did:web:other.example", SERVICE_DID, AssertionOperation.STATUS)));
        assertEquals(401, code(claiming(AGENT_DID, AGENT_DID, "did:web:elsewhere", AssertionOperation.STATUS)));
        assertEquals(401, code(claiming(AGENT_DID, AGENT_DID, SERVICE_DID, AssertionOperation.ENROLL)));
        assertEquals(401, code(claiming("did:key:z6Mk", "did:key:z6Mk", SERVICE_DID, AssertionOperation.STATUS)));
        assertEquals(401, code(claiming(null, null, SERVICE_DID, AssertionOperation.STATUS)));
    }

    @Test
    void replaysAreConsumedOnce() {
        AepService service =
                serviceBuilder(document(List.of(), Map.of(), List.of())).build();
        enroll(service);

        assertEquals(200, code(service.status(CommandOptions.authenticated("assertion-1"))));
        assertEquals(401, code(service.status(CommandOptions.authenticated("assertion-1"))));
        assertEquals(200, code(service.status(CommandOptions.authenticated("assertion-2"))));
    }

    @Test
    void refusesUnusableServiceConfiguration() {
        InspectDocument document = document(List.of(), Map.of(), List.of());

        assertThrows(
                IllegalArgumentException.class,
                () -> serviceBuilder(document).clockSkew(Duration.ofSeconds(-1)).build());
        assertThrows(
                IllegalArgumentException.class,
                () -> serviceBuilder(document).clockSkew(Duration.ofSeconds(31)).build());
        assertThrows(
                IllegalArgumentException.class,
                () -> serviceBuilder(document)
                        .clockSkew(Duration.ofMillis(1500))
                        .build());
        assertThrows(
                IllegalArgumentException.class,
                () -> serviceBuilder(document)
                        .inspectUri(URI.create("http://service.example/.well-known/aep"))
                        .build());
        assertThrows(
                IllegalArgumentException.class,
                () -> serviceBuilder(document(List.of(API_KEY), Map.of(API_KEY, config(List.of()))))
                        .build(),
                "an advertised Grant Type needs a handler");
        assertThrows(
                IllegalArgumentException.class,
                () -> serviceBuilder(document(List.of(), Map.of(), List.of(API_KEY)))
                        .build(),
                "an advertised authentication method needs a Grant Type");
        assertThrows(
                CompletionException.class,
                () -> serviceBuilder(document)
                        .identifierSupplier(() -> " ")
                        .build()
                        .enroll(enrollRequest(), CommandOptions.idempotent("e", ENROLL_KEY))
                        .toCompletableFuture()
                        .join());
    }

    @Test
    void acceptsEveryConfigurableCollaborator() {
        AepService service = serviceBuilder(document(List.of(), Map.of(), List.of()))
                .enrollmentStore(EnrollmentStore.inMemory())
                .enrollmentPolicy(EnrollmentPolicy.active())
                .replayStore(ReplayStore.inMemory())
                .idempotencyStore(IdempotencyStore.inMemory(CLOCK))
                .clockSkew(Duration.ofSeconds(5))
                .claimValueLimits(ClaimValueLimits.defaults())
                .inspectUri(URI.create("https://service.example/.well-known/aep"))
                .build();

        assertEquals(200, code(service.enroll(enrollRequest(), CommandOptions.idempotent("e", ENROLL_KEY))));
        var builder = serviceBuilder(document(List.of(), Map.of(), List.of()));
        assertThrows(NullPointerException.class, () -> builder.enrollmentStore(null));
        assertThrows(NullPointerException.class, () -> builder.enrollmentPolicy(null));
        assertThrows(NullPointerException.class, () -> builder.replayStore(null));
        assertThrows(NullPointerException.class, () -> builder.idempotencyStore(null));
        assertThrows(NullPointerException.class, () -> builder.clockSkew(null));
        assertThrows(NullPointerException.class, () -> builder.claimValueLimits(null));
        assertThrows(NullPointerException.class, () -> builder.identifierSupplier(null));
        assertThrows(NullPointerException.class, () -> builder.clock(null));
    }

    @Test
    void refusesDuplicateHandlerRegistrations() {
        var builder = serviceBuilder(document(List.of(API_KEY), Map.of(API_KEY, config(List.of()))));
        GrantTypeDefinition definition = new GrantTypeDefinition(API_KEY, handler());
        builder.grantType(definition);
        builder.credentialAuthenticator(API_KEY, handler());

        assertThrows(IllegalArgumentException.class, () -> builder.grantType(definition));
        assertThrows(IllegalArgumentException.class, () -> builder.credentialAuthenticator(API_KEY, handler()));
        assertThrows(NullPointerException.class, () -> builder.storedCredentialGrantType(null));
        assertEquals(API_KEY, definition.grantType());
    }

    @Test
    void refusesStoredCredentialConfigurationTheDocumentDoesNotAdvertise() {
        var builder = serviceBuilder(document(List.of(API_KEY), Map.of(API_KEY, config(List.of()))));
        StoredCredentialGrantType mismatched = StoredCredentialGrantTypes.apiKey(
                config(List.of("x-other")),
                (request, context) -> completed(apiKey(API_KEY_HEADER)),
                ServiceCredentialStore.inMemory());

        assertThrows(IllegalArgumentException.class, () -> builder.storedCredentialGrantType(mismatched));
        assertEquals(API_KEY, mismatched.grantType());
        assertEquals(config(List.of("x-other")), mismatched.config());
    }

    @Test
    void rejectsIssuedCredentialsThatDoNotMatchTheirGrantType() {
        assertThrows(
                CompletionException.class,
                ServiceCoverageTest::issueWrongCredentialType,
                "an api-key handler does not issue a bearer token");
        assertThrows(
                CompletionException.class,
                () -> issue((request, context) -> completed(apiKey("Bad Header"))),
                "the response still has to validate");
        assertThrows(
                CompletionException.class,
                () -> issue((request, context) ->
                        completed(new GrantResponses.ApiKey("s", "c", "whenever", API_KEY_HEADER, List.of()))),
                "the expiry has to be a date-time");
        assertThrows(
                CompletionException.class,
                () -> issue((request, context) -> completed(
                        new GrantResponses.ApiKey("s", "c", "2026-09-01T11:00:00Z", API_KEY_HEADER, List.of()))),
                "the expiry has to follow issuance");
        assertThrows(
                CompletionException.class,
                () -> issue((request, context) -> completed(apiKey("x-unadvertised"))),
                "the header has to be advertised");
    }

    @Test
    void rejectsCredentialStoresThatReturnAnUnusableMatch() {
        assertThrows(
                CompletionException.class,
                () -> matched(
                        new ServiceCredentialMatch(" ", "credential-1", NOW.plusSeconds(60), API_KEY, List.of())));
        assertThrows(
                CompletionException.class,
                () -> matched(new ServiceCredentialMatch(AGENT_DID, " ", NOW.plusSeconds(60), API_KEY, List.of())));
        assertThrows(
                CompletionException.class,
                () -> matched(new ServiceCredentialMatch(
                        AGENT_DID, "credential-1", NOW.minusSeconds(1), API_KEY, List.of())));
        assertThrows(
                CompletionException.class,
                () -> matched(new ServiceCredentialMatch(
                        AGENT_DID, "credential-1", NOW.plusSeconds(60), "other", List.of())));
        assertThrows(
                NullPointerException.class,
                () -> new ServiceCredentialMatch(AGENT_DID, "credential-1", null, API_KEY, List.of()));
    }

    @Test
    void rejectsAuthenticatorsThatReturnAnUnusablePrincipal() {
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
                                AGENT_DID,
                                API_KEY,
                                "credential-1",
                                API_KEY,
                                List.of(),
                                AuthenticatedPrincipal.Kind.AEP_JWT)));
                    }
                })
                .build();
        enroll(service);

        assertThrows(CompletionException.class, () -> authenticate(service, Map.of(API_KEY_HEADER, List.of("x"))));
    }

    @Test
    void refusesSessionCredentialsForAgentsThatAreNotActive() {
        EnrollmentStore store = EnrollmentStore.inMemory();
        AepService service = ServiceFixtures.storedCredentialService(ServiceCredentialStore.inMemory(), store);
        enroll(service);
        grant(service, API_KEY);
        store.save(EnrollmentRecord.builder(AGENT_DID, "enrollment-1", AgentStatus.TERMINATED, NOW)
                        .since(NOW)
                        .updatedAt(NOW)
                        .build())
                .toCompletableFuture()
                .join();

        assertEquals(NOT_RECOGNIZED, rejected(service, Map.of(API_KEY_HEADER, List.of("api-secret"))));
    }

    private static AepService apiKeyService() {
        return serviceBuilder(document(List.of(API_KEY), Map.of(API_KEY, config(List.of()))))
                .grantType(new GrantTypeDefinition(API_KEY, handler()))
                .credentialAuthenticator(API_KEY, handler())
                .build();
    }

    private static AepService jwtAndApiKeyService() {
        return serviceBuilder(document(
                        List.of(API_KEY),
                        Map.of(API_KEY, config(List.of(API_KEY_HEADER))),
                        List.of(Aep.AUTHENTICATION_METHOD_JWT, API_KEY)))
                .storedCredentialGrantType(StoredCredentialGrantTypes.apiKey(
                        config(List.of(API_KEY_HEADER)),
                        (request, context) -> completed(apiKey(API_KEY_HEADER)),
                        ServiceCredentialStore.inMemory()))
                .build();
    }

    private static AepService freshService() {
        return serviceBuilder(document(List.of(), Map.of(), List.of())).build();
    }

    private static GrantResponses.ApiKey apiKey(String header) {
        return new GrantResponses.ApiKey("api-secret", "api-1", EXPIRY, header, List.of("read"));
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private static void issueWrongCredentialType() {
        BuiltInCredentialIssuer raw = (BuiltInCredentialIssuer<GrantResponses.OAuthBearer>) (request, context) ->
                completed(new GrantResponses.OAuthBearer("s", "c", EXPIRY, List.of(), "opaque", "Bearer"));
        issue((BuiltInCredentialIssuer<GrantResponses.ApiKey>) raw);
    }

    private static void issue(BuiltInCredentialIssuer<GrantResponses.ApiKey> issuer) {
        AepService service = serviceBuilder(
                        document(List.of(API_KEY), Map.of(API_KEY, config(List.of(API_KEY_HEADER)))))
                .storedCredentialGrantType(StoredCredentialGrantTypes.apiKey(
                        config(List.of(API_KEY_HEADER)), issuer, ServiceCredentialStore.inMemory()))
                .build();
        enroll(service);
        service.grant(grantRequest(), CommandOptions.idempotent("g", GRANT_KEY))
                .toCompletableFuture()
                .join();
    }

    private static void matched(ServiceCredentialMatch match) {
        AepService service = serviceBuilder(document(List.of(API_KEY), Map.of(API_KEY, config(List.of()))))
                .storedCredentialGrantType(StoredCredentialGrantTypes.apiKey(
                        config(List.of()),
                        (request, context) -> completed(apiKey(API_KEY_HEADER)),
                        new MatchingStore(match)))
                .build();
        enroll(service);
        authenticate(service, Map.of(API_KEY_HEADER, List.of("api-secret")));
    }

    private static CompletionStage<? extends ServiceResponse<?>> claiming(
            String issuer, String subject, String audience, AssertionOperation operation) {
        AepService service = AepService.builder(
                        document(List.of(), Map.of(), List.of()),
                        (assertion, context) -> completed(new ClientAssertionClaims(
                                issuer,
                                subject,
                                audience,
                                operation,
                                NOW.minusSeconds(1).getEpochSecond(),
                                NOW.plusSeconds(60).getEpochSecond(),
                                assertion,
                                null)))
                .clock(CLOCK)
                .build();
        return service.status(CommandOptions.authenticated("assertion"));
    }

    private static void resource(AepService service, URI url) {
        service.authenticate(new ProtectedResourceRequest(Map.of(), "GET", url))
                .toCompletableFuture()
                .join();
    }

    private static EnrollRequest enrollRequest() {
        return new EnrollRequest(AGENT_DID, null, null);
    }

    private static GrantRequest grantRequest() {
        return new GrantRequest(API_KEY, List.of("read"));
    }

    private static CommandOptions key(String value, String assertion) {
        return CommandOptions.idempotent(assertion, value);
    }

    private static int code(CompletionStage<? extends ServiceResponse<?>> stage) {
        return stage.toCompletableFuture().join().status();
    }

    private static String rejected(AepService service, Map<String, List<String>> headers) {
        ProtectedResourceResult result = authenticate(service, headers);
        assertFalse(result.authenticated(), "expected a rejection");
        return result.response().problem().code();
    }

    private static RecordingHandler handler() {
        return new RecordingHandler();
    }

    private static final class RecordingHandler implements GrantTypeHandler, CredentialAuthenticator {
        @Override
        public CompletionStage<GrantResult> grant(GrantRequest request, GrantContext context) {
            return completed(new GrantResult("credential-1", Map.of("credential_id", "credential-1")));
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

    private record MatchingStore(ServiceCredentialMatch match) implements ServiceCredentialStore {
        @Override
        public CompletionStage<Optional<ServiceCredentialMatch>> authenticate(
                String grantType, CredentialAuthenticationInput input) {
            return completed(Optional.of(match));
        }

        @Override
        public CompletionStage<Boolean> hasPresentation(String grantType, CredentialAuthenticationInput input) {
            return completed(true);
        }

        @Override
        public CompletionStage<Void> revoke(String agentDid, String grantType, String credentialId, Instant revokedAt) {
            return completed(null);
        }

        @Override
        public CompletionStage<Void> revokeGrantType(String agentDid, String grantType, Instant revokedAt) {
            return completed(null);
        }

        @Override
        public CompletionStage<Void> save(ServiceCredentialRecord record) {
            return completed(null);
        }
    }
}
