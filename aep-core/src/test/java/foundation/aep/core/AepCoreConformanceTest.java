package foundation.aep.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Spec-grounded behaviour for the transport-independent contracts in Core. */
final class AepCoreConformanceTest {

    private static List<String> paths(List<ValidationIssue> issues) {
        return issues.stream().map(ValidationIssue::path).toList();
    }

    private static InspectDocument.Builder validDocument() {
        return InspectDocument.builder()
                .version(Aep.VERSION)
                .bindings(new InspectDocument.Bindings(List.of("http")))
                .commands(new InspectDocument.Commands(List.of("inspect"), List.of(), Map.of()))
                .core(new InspectDocument.Core(List.of("EdDSA", "ES256")))
                .http(new InspectDocument.Http("/aep/", null))
                .identity(new InspectDocument.Identity(List.of("did:web")))
                .service(new InspectDocument.Service("did:web:service.example"));
    }

    /**
     * CORE-AUTH-001 spells the credential grammar as {@code "AEP" 1*SP compact-jws}, so one or more
     * separators is the grammar rather than a malformed presentation, and trailing optional
     * whitespace belongs to the field value rather than to the credential.
     */
    @Test
    void acceptsTheRepeatedSeparatorTheCredentialGrammarAllows() {
        for (String value : List.of("AEP token", "AEP  token", "AEP\ttoken", "AEP \t token", "AEP token  ")) {
            ProtectedResourceAuthorization parsed = AepHttp.parseAuthorization(value, AuthorizationCarrier.STANDARD);
            assertEquals("token", parsed.credentials(), value);
            assertEquals(AuthorizationScheme.AEP, parsed.scheme(), value);
        }
        assertEquals(
                AuthorizationScheme.BEARER,
                AepHttp.parseAuthorization("bearer token", AuthorizationCarrier.STANDARD)
                        .scheme());
        assertEquals(
                AuthorizationScheme.BASIC,
                AepHttp.parseAuthorization("BASIC dXNlcjpwdw==", AuthorizationCarrier.STANDARD)
                        .scheme());
    }

    /**
     * The AEP, Bearer, and Basic grammars share a visible US-ASCII credential. A value carrying a
     * control character or an embedded CRLF is not a credential, and accepting one would let a
     * parsed presentation travel back into a request header through {@link AepHttp#renderAuthorization}.
     */
    @Test
    void rejectsCredentialsThatAreNotVisibleAscii() {
        for (String credentials : List.of("tok\ren", "tok\nen", "tok\u0001en", "tok\u007fen", "tokén")) {
            assertThrows(
                    AepAuthorizationException.class,
                    () -> AepHttp.parseAuthorization("AEP " + credentials, AuthorizationCarrier.STANDARD),
                    credentials);
            assertThrows(
                    AepAuthorizationException.class,
                    () -> AepHttp.renderAuthorization(new ProtectedResourceAuthorization(
                            AuthorizationCarrier.STANDARD, AuthorizationScheme.AEP, credentials)),
                    credentials);
        }
        assertEquals(
                Map.of("Authorization", "AEP token"),
                AepHttp.renderAuthorization(new ProtectedResourceAuthorization(
                        AuthorizationCarrier.STANDARD, AuthorizationScheme.AEP, "token")));
        assertEquals(
                Map.of(Aep.AUTHORIZATION_HEADER, "Bearer token"),
                AepHttp.renderAuthorization(new ProtectedResourceAuthorization(
                        AuthorizationCarrier.DEDICATED, AuthorizationScheme.BEARER, "token")));
    }

    /** CORE-PR-018: one dedicated field value must not encode more than one credential. */
    @Test
    void rejectsACombinedDedicatedPresentation() {
        assertThrows(
                AepAuthorizationException.class,
                () -> AepHttp.parseAuthorization("AEP one, Bearer two", AuthorizationCarrier.DEDICATED));
        assertEquals(
                "token",
                AepHttp.parseAuthorization("AEP token", AuthorizationCarrier.DEDICATED)
                        .credentials());
    }

    /**
     * CORE-CA-014 and CORE-CA-015: an authenticate assertion names one absolute HTTPS target with no
     * fragment. User information has no place in it either, because the request target a Service
     * compares the claim against never carries credentials.
     */
    @Test
    void boundsTheResourceClaimToASafeAbsoluteTarget() {
        for (String resource : List.of(
                "https://api.example/x#",
                "https://api.example/x#fragment",
                "https://user:secret@api.example/x",
                "http://api.example/x",
                "/x",
                "mailto:agent@example.com")) {
            assertFalse(
                    AepValidation.clientAssertionClaims(authenticateClaims(resource))
                            .isEmpty(),
                    resource);
        }
        assertTrue(AepValidation.clientAssertionClaims(authenticateClaims("https://api.example/x"))
                .isEmpty());
        assertTrue(AepValidation.clientAssertionClaims(authenticateClaims("https://api.example/x?q=1"))
                .isEmpty());
    }

    /** The development opt-in permits the three loopback literals a parsed URI actually presents. */
    @Test
    void permitsLoopbackResourcesOnlyUnderTheExplicitOptIn() {
        for (String resource : List.of("http://localhost/x", "http://127.0.0.1/x", "http://[::1]/x")) {
            assertFalse(
                    AepValidation.clientAssertionClaims(authenticateClaims(resource), false)
                            .isEmpty(),
                    resource);
            assertTrue(
                    AepValidation.clientAssertionClaims(authenticateClaims(resource), true)
                            .isEmpty(),
                    resource);
        }
        assertFalse(AepValidation.clientAssertionClaims(authenticateClaims("http://loopback.example/x"), true)
                .isEmpty());
    }

    /** CORE-CA-026: a non-authenticate assertion must not carry a resource. */
    @Test
    void keepsTheResourceClaimToAuthenticate() {
        ClientAssertionClaims claims = new ClientAssertionClaims(
                "did:web:agent.example",
                "did:web:agent.example",
                "did:web:service.example",
                AssertionOperation.ENROLL,
                1_000,
                1_060,
                "jti-1",
                "https://api.example/x");
        assertEquals(List.of("$.resource"), paths(AepValidation.clientAssertionClaims(claims)));
    }

    /** CORE-CA-019: the assertion lifetime is bounded at 300 seconds, and must be positive. */
    @Test
    void boundsTheAssertionLifetime() {
        assertTrue(
                AepValidation.clientAssertionClaims(commandClaims(1_000, 1_300)).isEmpty());
        assertTrue(
                AepValidation.clientAssertionClaims(commandClaims(1_000, 1_001)).isEmpty());
        assertEquals(List.of("$.exp"), paths(AepValidation.clientAssertionClaims(commandClaims(1_000, 1_301))));
        assertEquals(List.of("$.exp"), paths(AepValidation.clientAssertionClaims(commandClaims(1_000, 1_000))));
        assertEquals(List.of("$.exp"), paths(AepValidation.clientAssertionClaims(commandClaims(1_000, 999))));
        // Near the top of the clock the bound is guarded against overflow, and a lifetime that
        // cannot exceed 300 seconds without wrapping stays valid.
        assertTrue(AepValidation.clientAssertionClaims(commandClaims(Long.MAX_VALUE - 1, Long.MAX_VALUE))
                .isEmpty());
    }

    /** CORE-CA-010: iss and sub name the same Agent. */
    @Test
    void requiresTheIssuerAndSubjectToAgree() {
        ClientAssertionClaims claims = new ClientAssertionClaims(
                "did:web:agent.example",
                "did:web:other.example",
                "did:web:service.example",
                AssertionOperation.STATUS,
                1_000,
                1_060,
                "jti-1",
                null);
        assertEquals(List.of("$.sub"), paths(AepValidation.clientAssertionClaims(claims)));
    }

    /**
     * A did:web authority is concatenated back into the document URI, so it must be an authority and
     * nothing else. A value decoding to a query or fragment would yield a document URI whose query
     * swallows the did.json path, so it is rejected.
     */
    @Test
    void rejectsDidWebAuthoritiesThatAreNotPurelyAnAuthority() {
        for (String did : List.of(
                "did:web:example.com%3Fx=1",
                "did:web:example.com%23y", "did:web:user%40example.com", "did:web:example.com%2Fpath")) {
            assertThrows(IllegalArgumentException.class, () -> DidWeb.documentUri(did), did);
        }
        assertEquals(URI.create("https://example.com/.well-known/did.json"), DidWeb.documentUri("did:web:example.com"));
        assertEquals(
                URI.create("https://example.com:8443/.well-known/did.json"),
                DidWeb.documentUri("did:web:example.com%3A8443"));
    }

    /** DWB path components are single segments; traversal never reaches the resolved URL. */
    @Test
    void rejectsTraversalInDidWebPathComponents() {
        for (String did : List.of(
                "did:web:example.com:.:agent",
                "did:web:example.com:..:agent",
                "did:web:example.com:%2E%2E:agent",
                "did:web:example.com:a%2Fb",
                "did:web:example.com::agent")) {
            assertThrows(IllegalArgumentException.class, () -> DidWeb.documentUri(did), did);
        }
        assertEquals(
                URI.create("https://example.com/agents/one/did.json"),
                DidWeb.documentUri("did:web:example.com:agents:one"));
    }

    /**
     * CORE-OAS-003 and CORE-OAS-004: an advertised OpenAPI URL must not downgrade transport or carry
     * user information. A relative reference inherits the Inspect response transport and is fine.
     */
    @Test
    void appliesOpenApiTransportRulesToTheAdvertisedDocument() {
        for (String url : List.of(
                "http://docs.example/openapi.json",
                "https://user:secret@docs.example/openapi.json",
                "ftp://docs.example/openapi.json")) {
            InspectDocument document = validDocument()
                    .http(new InspectDocument.Http(
                            "/aep/", new InspectDocument.OpenApi(url, new InspectDocument.PathMatching("strict"))))
                    .build();
            assertTrue(paths(AepValidation.inspectDocument(document)).contains("$.http.openapi.url"), url);
        }
        for (String url : List.of(
                "/openapi.json",
                "openapi.json",
                "https://docs.example/openapi.json",
                "http://localhost:8080/openapi.json",
                "http://127.0.0.1/openapi.json",
                "http://[::1]/openapi.json")) {
            InspectDocument document = validDocument()
                    .http(new InspectDocument.Http(
                            "/aep/", new InspectDocument.OpenApi(url, new InspectDocument.PathMatching("strict"))))
                    .build();
            assertTrue(AepValidation.inspectDocument(document).isEmpty(), url);
        }
    }

    /**
     * An endpoint_base is origin-relative. A protocol-relative value would move every command URL to
     * another origin once resolved against the Service origin, so the document that advertises one is
     * invalid rather than merely unusable at the point a command path is built.
     */
    @Test
    void rejectsAnEndpointBaseThatCouldLeaveTheServiceOrigin() {
        for (String base : List.of("//attacker.example", "//attacker.example/aep", "aep/", "/aep?x=1", "/aep#y")) {
            InspectDocument document =
                    validDocument().http(new InspectDocument.Http(base, null)).build();
            assertTrue(paths(AepValidation.inspectDocument(document)).contains("$.http.endpoint_base"), base);
            assertThrows(IllegalArgumentException.class, () -> AepHttp.normalizeEndpointBase(base), base);
        }
        assertTrue(AepValidation.inspectDocument(validDocument()
                        .http(new InspectDocument.Http("/aep", null))
                        .build())
                .isEmpty());
    }

    /** CORE-HTTP-003 and CORE-HTTP-004: both /aep and /aep/ produce /aep/enroll. */
    @Test
    void buildsCommandPathsFromTheAdvertisedBase() {
        assertEquals(Aep.DEFAULT_ENDPOINT_BASE, AepHttp.normalizeEndpointBase(null));
        assertEquals("/aep/", AepHttp.normalizeEndpointBase("/aep"));
        assertEquals("/aep/enroll", AepHttp.commandPath(AepCommand.ENROLL, "/aep"));
        assertEquals("/aep/enroll", AepHttp.commandPath(AepCommand.ENROLL, "/aep/"));
        assertEquals("/v1/aep/status", AepHttp.commandPath(AepCommand.STATUS, "/v1/aep"));
        assertEquals(
                URI.create("https://api.example/aep/grant"),
                AepHttp.commandUri(URI.create("https://api.example/"), AepCommand.GRANT, null));
        // Inspect is served from the well-known path, never from endpoint_base.
        assertThrows(IllegalArgumentException.class, () -> AepHttp.commandPath(AepCommand.INSPECT, "/aep/"));
    }

    /** CORE-INS-009 and CORE-INS-022 constrain what a document may advertise. */
    @Test
    void constrainsTheAdvertisedCommandSet() {
        InspectDocument withoutGrantTypes = validDocument()
                .commands(new InspectDocument.Commands(List.of("inspect", "grant", "revoke"), List.of(), Map.of()))
                .build();
        assertTrue(paths(AepValidation.inspectDocument(withoutGrantTypes)).contains("$.commands.grant_types"));

        InspectDocument withoutIdentity = validDocument()
                .commands(new InspectDocument.Commands(List.of("inspect", "enroll"), List.of(), Map.of()))
                .identity(new InspectDocument.Identity(List.of()))
                .build();
        assertTrue(paths(AepValidation.inspectDocument(withoutIdentity)).contains("$.identity.methods"));

        // CORE-IANA-005: authenticate is an assertion operation, never a command.
        InspectDocument withAuthenticate = validDocument()
                .commands(new InspectDocument.Commands(List.of("inspect", "authenticate"), List.of(), Map.of()))
                .build();
        assertTrue(paths(AepValidation.inspectDocument(withAuthenticate)).contains("$.commands.supported"));

        InspectDocument withoutInspect = validDocument()
                .commands(new InspectDocument.Commands(List.of("enroll"), List.of(), Map.of()))
                .build();
        assertTrue(paths(AepValidation.inspectDocument(withoutInspect)).contains("$.commands.supported"));
    }

    /**
     * CORE-CA-003: a Service must advertise both required algorithms. The document schema leaves the
     * array open beyond those two so an extension can register another algorithm, and the allow-list
     * that keeps `none` and symmetric algorithms out of an assertion lives at verification time.
     */
    @Test
    void requiresTheRegisteredSigningAlgorithms() {
        for (List<String> algorithms : List.of(List.<String>of(), List.of("EdDSA"), List.of("ES256"))) {
            assertFalse(
                    AepValidation.inspectDocument(validDocument()
                                    .core(new InspectDocument.Core(algorithms))
                                    .build())
                            .isEmpty(),
                    algorithms.toString());
        }
        for (List<String> algorithms : List.of(List.of("ES256", "EdDSA"), List.of("EdDSA", "ES256", "ML-DSA-44"))) {
            assertTrue(
                    AepValidation.inspectDocument(validDocument()
                                    .core(new InspectDocument.Core(algorithms))
                                    .build())
                            .isEmpty(),
                    algorithms.toString());
        }
        // CORE-CA-005: an advertised symmetric algorithm still never verifies an assertion.
        assertThrows(
                IllegalArgumentException.class,
                () -> ClientAssertions.verify(
                        "a.b.c",
                        null,
                        ClientAssertionVerification.builder(
                                        "did:web:service.example", "did:web:agent.example", AssertionOperation.STATUS)
                                .build()));
    }

    /** CORE-ERR-002, CORE-ERR-003 and CORE-ERR-007 shape a Problem Details response. */
    @Test
    void shapesProblemDetails() {
        assertTrue(AepValidation.problemDetails(ProblemDetails.of("not_recognized", "Not recognized", 401))
                .isEmpty());
        assertTrue(paths(AepValidation.problemDetails(new ProblemDetails(
                        "urn:aep:error:other", "Title", 401, null, null, "not_recognized", null, null, null)))
                .contains("$.type"));
        assertTrue(paths(AepValidation.problemDetails(
                        new ProblemDetails("urn:aep:error:bad", "", 400, null, null, "bad", null, null, null)))
                .contains("$.title"));
        assertTrue(paths(AepValidation.problemDetails(new ProblemDetails(
                        "urn:aep:error:Bad-Code", "Title", 400, null, null, "Bad-Code", null, null, null)))
                .contains("$.code"));
        // A not_recognized response stays non-disclosing.
        assertTrue(paths(AepValidation.problemDetails(new ProblemDetails(
                        "urn:aep:error:not_recognized",
                        "Not recognized",
                        401,
                        null,
                        null,
                        "not_recognized",
                        "true",
                        null,
                        null)))
                .contains("$"));
        assertTrue(paths(AepValidation.problemDetails(new ProblemDetails(
                        "urn:aep:error:not_recognized",
                        "Not recognized",
                        401,
                        null,
                        null,
                        "not_recognized",
                        null,
                        List.of("contact.email"),
                        null)))
                .contains("$"));
        // The same metadata is legitimate on a lifecycle problem.
        assertTrue(AepValidation.problemDetails(new ProblemDetails(
                        "urn:aep:error:verification_pending",
                        "Verification pending",
                        403,
                        null,
                        null,
                        "verification_pending",
                        "true",
                        List.of("contact.email"),
                        List.of("domain-control")))
                .isEmpty());
    }

    /** CORE-RVK-006 and CORE-RVK-008: the Revoke targets are mutually exclusive. */
    @Test
    void constrainsRevokeTargeting() {
        assertTrue(AepValidation.revokeRequest(new RevokeRequest("api-key", null, null))
                .isEmpty());
        assertTrue(AepValidation.revokeRequest(new RevokeRequest("api-key", "credential-1", null))
                .isEmpty());
        assertTrue(AepValidation.revokeRequest(new RevokeRequest(null, null, "true"))
                .isEmpty());
        for (RevokeRequest request : List.of(
                new RevokeRequest(null, null, null),
                new RevokeRequest(null, "credential-1", null),
                new RevokeRequest("api-key", null, "true"),
                new RevokeRequest(null, "credential-1", "true"),
                new RevokeRequest(null, null, "false"))) {
            assertFalse(AepValidation.revokeRequest(request).isEmpty(), request.toString());
        }
    }

    /** APK-RSP-004 and RFC 7617 keep issued credentials unambiguous on the wire. */
    @Test
    void constrainsIssuedCredentialShapes() {
        assertTrue(AepValidation.grantResponse(new GrantResponses.ApiKey(
                        "key-value", "credential-1", "2026-09-01T12:00:00Z", "x-api-key", List.of("read")))
                .isEmpty());
        for (String apiKey : List.of("key value", "key\"value", "key,value", "key;value", "key\\value", "key\u0001")) {
            assertTrue(
                    paths(AepValidation.grantResponse(new GrantResponses.ApiKey(
                                    apiKey, "credential-1", "2026-09-01T12:00:00Z", "x-api-key", null)))
                            .contains("$.api_key"),
                    apiKey);
        }
        assertTrue(paths(AepValidation.grantResponse(
                        new GrantResponses.ApiKey("key", "credential-1", "2026-09-01T12:00:00Z", "bad header", null)))
                .contains("$.header"));
        assertTrue(paths(AepValidation.grantResponse(new GrantResponses.Basic(
                        "credential-1", "2026-09-01T12:00:00Z", "secret", null, null, "user:name")))
                .contains("$.username"));
        assertTrue(paths(AepValidation.grantResponse(new GrantResponses.Basic(
                        "credential-1", "2026-09-01T12:00:00Z", "sec\u0001ret", null, null, "user")))
                .contains("$.password"));
        assertTrue(paths(AepValidation.grantResponse(
                        new GrantResponses.OAuthBearer("token", "credential-1", "2026-09-01T12:00:00Z", null, "MAC")))
                .contains("$.token_type"));
        assertTrue(paths(AepValidation.grantResponse(new GrantResponses.OAuthBearer(
                        "token", "credential-1", "2026-09-01T12:00:00Z", null, "saml", "Bearer")))
                .contains("$.token_format"));
        assertTrue(AepValidation.grantResponse(new GrantResponses.OAuthBearer(
                        "token", "credential-1", "2026-09-01T12:00:00Z", List.of(), "jwt", "Bearer"))
                .isEmpty());
    }

    /** PLT-VER-009: an unrecognized verification response discloses nothing about an identity. */
    @Test
    void keepsUnrecognizedVerificationResponsesNonDisclosing() {
        assertTrue(AepValidation.platformVerificationResponse(new PlatformVerificationResponse(
                        null, null, null, "not_recognized", "did:web:service.example", null, false))
                .isEmpty());
        assertTrue(paths(AepValidation.platformVerificationResponse(new PlatformVerificationResponse(
                        "did:web:agent.example", null, null, "not_recognized", "did:web:service.example", null, false)))
                .contains("$"));
        assertTrue(paths(AepValidation.platformVerificationResponse(new PlatformVerificationResponse(
                        null, null, null, "verified", "did:web:service.example", null, false)))
                .contains("$.reason"));
        assertTrue(AepValidation.platformVerificationResponse(new PlatformVerificationResponse(
                        "did:web:agent.example",
                        "pai_1",
                        AssertionOperation.STATUS,
                        "verified",
                        "did:web:service.example",
                        ManagedAgentStatus.ACTIVE,
                        true))
                .isEmpty());
    }

    /** RFC 5321: a standardized address-literal tag is an Ldh-str, which starts alphanumeric. */
    @Test
    void constrainsMailboxSyntax() {
        for (String mailbox : List.of(
                "agent@example.com",
                "\"quoted local\"@example.com",
                "agent@[127.0.0.1]",
                "agent@[IPv6:::1]",
                "agent@[x25:value]")) {
            assertTrue(
                    AepValidation.claimValues(
                                    ClaimValues.builder().contactEmail(mailbox).build())
                            .isEmpty(),
                    mailbox);
        }
        for (String mailbox : List.of(
                "agent@[-tag:value]",
                "agent@[:value]",
                "agent@[tag:]",
                "agent@@example.com",
                "@example.com",
                "agent@",
                "agent..name@example.com",
                "agent@-example.com",
                "agent@[not closed")) {
            assertFalse(
                    AepValidation.claimValues(
                                    ClaimValues.builder().contactEmail(mailbox).build())
                            .isEmpty(),
                    mailbox);
        }
    }

    private static ClientAssertionClaims authenticateClaims(String resource) {
        return new ClientAssertionClaims(
                "did:web:agent.example",
                "did:web:agent.example",
                "did:web:service.example",
                AssertionOperation.AUTHENTICATE,
                1_000,
                1_060,
                "jti-1",
                resource);
    }

    private static ClientAssertionClaims commandClaims(long issuedAt, long expiresAt) {
        return new ClientAssertionClaims(
                "did:web:agent.example",
                "did:web:agent.example",
                "did:web:service.example",
                AssertionOperation.STATUS,
                issuedAt,
                expiresAt,
                "jti-1",
                null);
    }
}
