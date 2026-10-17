package foundation.aep.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Failure paths that only a malformed input or an unusual key reaches. */
final class AepCoreEdgeTest {
    private static final Instant NOW = Instant.parse("2026-09-01T12:00:00Z");
    private static final String AGENT = "did:web:agent.example";
    private static final String SERVICE = "did:web:service.example";

    @Test
    void jsonUseWithoutAnAdapterReportsTheMissingDependency() {
        ExceptionInInitializerError failure =
                assertThrows(ExceptionInInitializerError.class, () -> AepJson.parseObject("{}", "example"));
        assertTrue(failure.getCause() instanceof IllegalStateException);
        assertEquals(
                "Exactly one AEP JSON adapter is required; found 0.",
                failure.getCause().getMessage());
    }

    private static List<String> paths(List<ValidationIssue> issues) {
        return issues.stream().map(ValidationIssue::path).toList();
    }

    private static ClientAssertionClaims claims(AssertionOperation operation, String resource) {
        return new ClientAssertionClaims(
                AGENT,
                AGENT,
                SERVICE,
                operation,
                NOW.getEpochSecond(),
                NOW.plusSeconds(300).getEpochSecond(),
                "assertion-1",
                resource);
    }

    private static ClientAssertionVerification verification(AssertionOperation operation, String resource) {
        return ClientAssertionVerification.builder(SERVICE, AGENT, operation)
                .resource(resource)
                .clock(Clock.fixed(NOW, ZoneOffset.UTC))
                .clockSkew(Duration.ZERO)
                .build();
    }

    /** The verification key decides the algorithm, so a token cannot choose a weaker one. */
    @Test
    void bindsTheAlgorithmToTheVerificationKey() throws JOSEException {
        JWK ecKey = new ECKeyGenerator(Curve.P_256).generate();
        JWK edKey = new OctetKeyPairGenerator(Curve.Ed25519).generate();
        String ecToken = ClientAssertions.sign(claims(AssertionOperation.ENROLL, null), ecKey, AGENT);

        assertEquals(
                claims(AssertionOperation.ENROLL, null),
                ClientAssertions.verify(ecToken, ecKey.toPublicJWK(), verification(AssertionOperation.ENROLL, null)));
        // An EdDSA key never verifies an ES256 token, and the failure is the common one.
        assertThrows(
                IllegalArgumentException.class,
                () -> ClientAssertions.verify(
                        ecToken, edKey.toPublicJWK(), verification(AssertionOperation.ENROLL, null)));
        // A second key of the same type does not verify another Agent's signature.
        JWK otherKey = new ECKeyGenerator(Curve.P_256).generate();
        assertThrows(
                IllegalArgumentException.class,
                () -> ClientAssertions.verify(
                        ecToken, otherKey.toPublicJWK(), verification(AssertionOperation.ENROLL, null)));
    }

    /** AEP assertions are signed with P-256 or Ed25519; nothing else is a usable key. */
    @Test
    void rejectsUnusableSigningAndVerificationKeys() throws JOSEException {
        JWK rsaKey = new RSAKeyGenerator(2048).generate();
        JWK p384Key = new ECKeyGenerator(Curve.P_384).generate();
        JWK x25519Key = new OctetKeyPairGenerator(Curve.X25519).generate();
        for (JWK key : List.of(rsaKey, p384Key, x25519Key)) {
            assertThrows(
                    IllegalArgumentException.class,
                    () -> ClientAssertions.sign(claims(AssertionOperation.STATUS, null), key, AGENT),
                    key.getKeyType().toString());
            assertThrows(
                    IllegalArgumentException.class,
                    () -> ClientAssertions.verify("a.b.c", key, verification(AssertionOperation.STATUS, null)),
                    key.getKeyType().toString());
        }
    }

    /** CORE-CA-008: the DID portion of kid must be the Agent the claims name. */
    @Test
    void requiresTheKeyIdToNameTheClaimedAgent() throws JOSEException {
        JWK key = new ECKeyGenerator(Curve.P_256).generate();
        assertThrows(
                IllegalArgumentException.class,
                () -> ClientAssertions.sign(claims(AssertionOperation.STATUS, null), key, "did:web:other.example"));
        assertThrows(
                IllegalArgumentException.class,
                () -> ClientAssertions.sign(
                        new ClientAssertionClaims(
                                AGENT,
                                "did:web:other.example",
                                SERVICE,
                                AssertionOperation.STATUS,
                                NOW.getEpochSecond(),
                                NOW.plusSeconds(60).getEpochSecond(),
                                "j",
                                null),
                        key,
                        AGENT));
        // A fragment selects a verification method and does not change the DID.
        String token = ClientAssertions.sign(claims(AssertionOperation.STATUS, null), key, AGENT + "#key-1");
        assertEquals(
                AGENT,
                ClientAssertions.verify(token, key.toPublicJWK(), verification(AssertionOperation.STATUS, null))
                        .issuer());
        // An absent key identifier falls back to the issuer.
        String implied = ClientAssertions.sign(claims(AssertionOperation.STATUS, null), key, null);
        assertEquals(
                AGENT,
                ClientAssertions.verify(implied, key.toPublicJWK(), verification(AssertionOperation.STATUS, null))
                        .issuer());
    }

    /** Claims that do not validate never leave the signer, and never come back from a verifier. */
    @Test
    void refusesClaimsThatDoNotValidate() throws JOSEException {
        JWK key = new ECKeyGenerator(Curve.P_256).generate();
        ClientAssertionClaims overlong = new ClientAssertionClaims(
                AGENT,
                AGENT,
                SERVICE,
                AssertionOperation.STATUS,
                NOW.getEpochSecond(),
                NOW.plusSeconds(301).getEpochSecond(),
                "assertion-1",
                null);
        AepValidationException failure =
                assertThrows(AepValidationException.class, () -> ClientAssertions.sign(overlong, key, AGENT));
        assertEquals("client assertion claims", failure.documentType());

        // An authenticate assertion needs a resource the loopback opt-in agrees with.
        ClientAssertionClaims loopback = claims(AssertionOperation.AUTHENTICATE, "http://localhost/x");
        assertThrows(AepValidationException.class, () -> ClientAssertions.sign(loopback, key, AGENT));
        String signed = ClientAssertions.sign(loopback, key, AGENT, true);
        assertEquals(
                loopback,
                ClientAssertions.verify(
                        signed,
                        key.toPublicJWK(),
                        ClientAssertionVerification.builder(SERVICE, AGENT, AssertionOperation.AUTHENTICATE)
                                .resource("http://localhost/x")
                                .clock(Clock.fixed(NOW, ZoneOffset.UTC))
                                .clockSkew(Duration.ZERO)
                                .allowInsecureLoopback(true)
                                .build()));
        // The same token is not recognized when the verifier does not permit loopback.
        assertThrows(
                AepValidationException.class,
                () -> ClientAssertions.verify(
                        signed,
                        key.toPublicJWK(),
                        ClientAssertionVerification.builder(SERVICE, AGENT, AssertionOperation.AUTHENTICATE)
                                .resource("http://localhost/x")
                                .clock(Clock.fixed(NOW, ZoneOffset.UTC))
                                .clockSkew(Duration.ZERO)
                                .build()));
    }

    @Test
    void rejectsTokensThatAreNotSignedAepAssertions() throws JOSEException {
        JWK key = new ECKeyGenerator(Curve.P_256).generate();
        for (String token : List.of("", "not-a-token", "a.b.c", "a.b")) {
            assertThrows(
                    IllegalArgumentException.class,
                    () -> ClientAssertions.verify(
                            token, key.toPublicJWK(), verification(AssertionOperation.STATUS, null)),
                    token);
            assertThrows(IllegalArgumentException.class, () -> ClientAssertions.decodeUnverified(token), token);
        }
        String token = ClientAssertions.sign(claims(AssertionOperation.STATUS, null), key, AGENT);
        assertEquals(claims(AssertionOperation.STATUS, null), ClientAssertions.decodeUnverified(token));
        // The operation and the clock are both part of recognition.
        assertThrows(
                IllegalArgumentException.class,
                () -> ClientAssertions.verify(token, key.toPublicJWK(), verification(AssertionOperation.GRANT, null)));
        assertThrows(
                IllegalArgumentException.class,
                () -> ClientAssertions.verify(
                        token,
                        key.toPublicJWK(),
                        ClientAssertionVerification.builder(SERVICE, AGENT, AssertionOperation.STATUS)
                                .clock(Clock.fixed(NOW.plusSeconds(3_600), ZoneOffset.UTC))
                                .clockSkew(Duration.ZERO)
                                .build()));
        assertThrows(
                IllegalArgumentException.class,
                () -> ClientAssertions.verify(
                        token,
                        key.toPublicJWK(),
                        ClientAssertionVerification.builder(SERVICE, AGENT, AssertionOperation.STATUS)
                                .clock(Clock.fixed(NOW.minusSeconds(3_600), ZoneOffset.UTC))
                                .clockSkew(Duration.ZERO)
                                .build()));
    }

    @Test
    void reportsAbsentInspectSubObjects() {
        InspectDocument document = InspectDocument.builder()
                .version(Aep.VERSION)
                .service(new InspectDocument.Service("did:web:service.example"))
                .build();
        List<String> reported = paths(AepValidation.inspectDocument(document));
        for (String expected : List.of("$.bindings", "$.commands", "$.core", "$.http", "$.identity")) {
            assertTrue(reported.contains(expected), expected + " in " + reported);
        }
        assertTrue(paths(AepValidation.inspectDocument(
                        InspectDocument.builder().version(Aep.VERSION).build()))
                .contains("$.service.did"));
    }

    /** CORE-INS: the advertised authentication method list is bounded. */
    @Test
    void boundsTheAdvertisedAuthenticationMethods() {
        List<String> methods = new ArrayList<>();
        for (int index = 0; index < 17; index++) {
            methods.add("method-" + index);
        }
        InspectDocument document = InspectDocument.builder()
                .version(Aep.VERSION)
                .authentication(new InspectDocument.Authentication(methods))
                .bindings(new InspectDocument.Bindings(List.of("http")))
                .commands(new InspectDocument.Commands(List.of("inspect"), List.of(), Map.of()))
                .core(new InspectDocument.Core(List.of("EdDSA", "ES256")))
                .http(new InspectDocument.Http("/aep/", null))
                .identity(new InspectDocument.Identity(List.of("did:web")))
                .service(new InspectDocument.Service("did:web:service.example"))
                .build();
        assertTrue(paths(AepValidation.inspectDocument(document)).contains("$.authentication.methods"));
    }

    @Test
    void validatesMailboxLocalAndDomainForms() {
        for (String mailbox : List.of(
                "\"escaped \\\" quote\"@example.com",
                "\"with@at\"@example.com",
                "agent@[IPv6:2001:db8::1]",
                "agent@[IPv6:::]",
                "agent@[0.0.0.0]",
                "a.b.c@example.co.uk",
                "agent@[01.2.3.4]")) {
            assertTrue(
                    AepValidation.claimValues(
                                    ClaimValues.builder().contactEmail(mailbox).build())
                            .isEmpty(),
                    mailbox);
        }
        for (String mailbox : List.of(
                "\"unterminated@example.com",
                "\"quote\"x@example.com",
                "\"\\\u0001\"@example.com",
                "\"ctl\u0001\"@example.com",
                "\"trailing\\\\\"@example.com".replace("\\\\", "\\"),
                "agent@[IPv6:2001:db8::1::2]",
                "agent@[IPv6:2001:db8:0:0:0:0:0:0:1]",
                "agent@[256.0.0.1]",
                "agent@[1.2.3]",
                "agent@[1.2.3.4.5]",
                "agent@[1234.2.3.4]",
                "agent@example..com",
                "a".repeat(65) + "@example.com",
                "agent@" + ("a".repeat(63) + ".").repeat(4) + "example.com")) {
            assertFalse(
                    AepValidation.claimValues(
                                    ClaimValues.builder().contactEmail(mailbox).build())
                            .isEmpty(),
                    mailbox);
        }
    }

    @Test
    void validatesIpv4MappedAndCompressedIpv6Literals() {
        for (String literal : List.of("[IPv6:::ffff:127.0.0.1]", "[IPv6:2001:db8::]", "[IPv6:::1]")) {
            assertTrue(
                    AepValidation.claimValues(ClaimValues.builder()
                                    .contactEmail("agent@" + literal)
                                    .build())
                            .isEmpty(),
                    literal);
        }
        for (String literal : List.of("[IPv6:127.0.0.1:1]", "[IPv6:gggg::1]", "[IPv6:]", "[IPv6:1:2:3:4:5:6:7:8:9]")) {
            assertFalse(
                    AepValidation.claimValues(ClaimValues.builder()
                                    .contactEmail("agent@" + literal)
                                    .build())
                            .isEmpty(),
                    literal);
        }
    }

    @Test
    void rejectsValuesThatAreNotParseableUris() {
        // An unparseable URI is reported rather than thrown from every URI-shaped validator.
        assertFalse(AepValidation.clientAssertionClaims(new ClientAssertionClaims(
                        AGENT, AGENT, SERVICE, AssertionOperation.AUTHENTICATE, 1_000, 1_060, "j", "http://[bad"))
                .isEmpty());
        assertTrue(paths(AepValidation.platformAgentIdentity(new PlatformAgentIdentity(
                        AGENT,
                        "pai_1",
                        "2026-09-01T12:00:00Z",
                        "https://[bad",
                        AGENT,
                        SERVICE,
                        List.of("ES256"),
                        ManagedAgentStatus.ACTIVE,
                        "2026-09-01T12:00:00Z")))
                .contains("$.did_document_url"));
        PlatformDiscoveryDocument discovery = new PlatformDiscoveryDocument(
                Aep.VERSION,
                new PlatformDiscoveryDocument.Endpoints(
                        null, "/x/{agent_identity_id}", "/x", "/x", "/x/{agent_identity_id}"),
                new PlatformDiscoveryDocument.Http("/x"),
                new PlatformDiscoveryDocument.Identity(List.of("did:web"), "https://[bad/{agent_did_id}"),
                new PlatformDiscoveryDocument.Platform(null, false, "Example"),
                new PlatformDiscoveryDocument.Signing(List.of("EdDSA", "ES256"), "300"));
        assertTrue(paths(AepValidation.platformDiscoveryDocument(discovery)).contains("$.identity.did_url_template"));
    }

    @Test
    void validatesNumericStringsAcrossTheirRanges() {
        InspectDocument.GrantTypeConfig config = new InspectDocument.GrantTypeConfig(
                null, "99999999999999999999999", null, null, null, "true", null, null);
        InspectDocument document = InspectDocument.builder()
                .version(Aep.VERSION)
                .bindings(new InspectDocument.Bindings(List.of("http")))
                .commands(new InspectDocument.Commands(
                        List.of("inspect", "grant", "revoke"), List.of("api-key"), Map.of("api-key", config)))
                .core(new InspectDocument.Core(List.of("EdDSA", "ES256")))
                .http(new InspectDocument.Http("/aep/", null))
                .identity(new InspectDocument.Identity(List.of("did:web")))
                .service(new InspectDocument.Service("did:web:service.example"))
                .build();
        // A default lifetime is an unbounded positive integer string at this level.
        assertTrue(AepValidation.inspectDocument(document).isEmpty());

        for (String value : List.of("0", "-1", "+1", "01", "", "x", "1.0")) {
            InspectDocument.GrantTypeConfig invalid =
                    new InspectDocument.GrantTypeConfig(null, value, null, null, null, "true", null, null);
            InspectDocument bad = InspectDocument.builder()
                    .version(Aep.VERSION)
                    .bindings(new InspectDocument.Bindings(List.of("http")))
                    .commands(new InspectDocument.Commands(
                            List.of("inspect", "grant", "revoke"), List.of("api-key"), Map.of("api-key", invalid)))
                    .core(new InspectDocument.Core(List.of("EdDSA", "ES256")))
                    .http(new InspectDocument.Http("/aep/", null))
                    .identity(new InspectDocument.Identity(List.of("did:web")))
                    .service(new InspectDocument.Service("did:web:service.example"))
                    .build();
            assertTrue(
                    paths(AepValidation.inspectDocument(bad))
                            .contains("$.commands.grant_types_config.api-key.default_lifetime_seconds"),
                    value);
        }
    }

    @Test
    void reportsEveryRegisteredClaimByName() {
        ClaimValues values = ClaimValues.builder()
                .contactAddressPrimary(new ContactAddressPrimary(
                        null, "US", "Ada", "Lovelace", "1 Main Street", null, null, null, null))
                .contactEmail("agent@example.com")
                .contactMobile("+14155550123")
                .personBirthdate("1815-12-10")
                .personFirstName("Ada")
                .personLastName("Lovelace")
                .personUsername("ada")
                .build();
        for (String name : Aep.REGISTERED_CLAIMS) {
            assertTrue(values.contains(name), name);
        }
        ClaimValues empty = ClaimValues.builder().build();
        for (String name : Aep.REGISTERED_CLAIMS) {
            assertFalse(empty.contains(name), name);
        }
        assertFalse(empty.contains("example.absent"));
    }

    @Test
    void resolvesLoopbackDidWebIdentifiersInEveryLiteralForm() {
        assertEquals(
                java.net.URI.create("http://localhost/.well-known/did.json"),
                DidWeb.documentUri("did:web:localhost", true));
        assertEquals(
                java.net.URI.create("http://[::1]/.well-known/did.json"),
                DidWeb.documentUri("did:web:%5B%3A%3A1%5D", true));
        assertEquals(
                java.net.URI.create("https://[::1]/.well-known/did.json"),
                DidWeb.documentUri("did:web:%5B%3A%3A1%5D", false));
    }

    @Test
    void copiesPlatformContextDefensively() {
        Map<String, Object> context = new java.util.LinkedHashMap<>();
        context.put("tenant", "acme");
        context.put("nested", new java.util.LinkedHashMap<>(Map.of("deep", List.of(1, 2))));
        PlatformSignRequest request =
                new PlatformSignRequest("jti-1", null, AssertionOperation.STATUS, context, null, SERVICE);
        context.put("tenant", "other");
        assertEquals("acme", request.platformContext().get("tenant"));
        assertThrows(
                UnsupportedOperationException.class,
                () -> request.platformContext().put("added", "value"));
        assertNull(new PlatformSignRequest("jti-1", null, AssertionOperation.STATUS, null, null, SERVICE)
                .platformContext());
        assertEquals(new RevokeResponse(), new RevokeResponse());
    }

    /** A JOSE header that is not an AEP client assertion header never reaches claim validation. */
    @Test
    void rejectsJoseHeadersThatAreNotAepAssertions() throws Exception {
        com.nimbusds.jose.jwk.ECKey key = new ECKeyGenerator(Curve.P_256).generate();
        com.nimbusds.jwt.JWTClaimsSet claimsSet = new com.nimbusds.jwt.JWTClaimsSet.Builder()
                .issuer(AGENT)
                .subject(AGENT)
                .audience(AGENT)
                .issueTime(java.util.Date.from(NOW))
                .expirationTime(java.util.Date.from(NOW.plusSeconds(60)))
                .jwtID("assertion-1")
                .claim("op", "status")
                .build();

        // CORE-CA-006: typ must be JWT.
        com.nimbusds.jwt.SignedJWT wrongType = new com.nimbusds.jwt.SignedJWT(
                new com.nimbusds.jose.JWSHeader.Builder(com.nimbusds.jose.JWSAlgorithm.ES256)
                        .type(new com.nimbusds.jose.JOSEObjectType("at+jwt"))
                        .keyID(AGENT)
                        .build(),
                claimsSet);
        wrongType.sign(new com.nimbusds.jose.crypto.ECDSASigner(key));
        assertThrows(
                IllegalArgumentException.class,
                () -> ClientAssertions.verify(
                        wrongType.serialize(), key.toPublicJWK(), verification(AssertionOperation.STATUS, null)));

        // CORE-CA-002: kid is required.
        com.nimbusds.jwt.SignedJWT noKeyId = new com.nimbusds.jwt.SignedJWT(
                new com.nimbusds.jose.JWSHeader.Builder(com.nimbusds.jose.JWSAlgorithm.ES256)
                        .type(com.nimbusds.jose.JOSEObjectType.JWT)
                        .build(),
                claimsSet);
        noKeyId.sign(new com.nimbusds.jose.crypto.ECDSASigner(key));
        assertThrows(
                IllegalArgumentException.class,
                () -> ClientAssertions.verify(
                        noKeyId.serialize(), key.toPublicJWK(), verification(AssertionOperation.STATUS, null)));

        // CORE-CA-005: a symmetric algorithm is refused before any key is consulted.
        byte[] secret = new byte[32];
        java.util.Arrays.fill(secret, (byte) 7);
        com.nimbusds.jwt.SignedJWT symmetric = new com.nimbusds.jwt.SignedJWT(
                new com.nimbusds.jose.JWSHeader.Builder(com.nimbusds.jose.JWSAlgorithm.HS256)
                        .type(com.nimbusds.jose.JOSEObjectType.JWT)
                        .keyID(AGENT)
                        .build(),
                claimsSet);
        symmetric.sign(new com.nimbusds.jose.crypto.MACSigner(secret));
        assertThrows(
                IllegalArgumentException.class,
                () -> ClientAssertions.verify(
                        symmetric.serialize(), key.toPublicJWK(), verification(AssertionOperation.STATUS, null)));

        // An assertion binds to exactly one audience.
        com.nimbusds.jwt.SignedJWT manyAudiences = new com.nimbusds.jwt.SignedJWT(
                new com.nimbusds.jose.JWSHeader.Builder(com.nimbusds.jose.JWSAlgorithm.ES256)
                        .type(com.nimbusds.jose.JOSEObjectType.JWT)
                        .keyID(AGENT)
                        .build(),
                new com.nimbusds.jwt.JWTClaimsSet.Builder(claimsSet)
                        .audience(List.of(SERVICE, "did:web:other.example"))
                        .build());
        manyAudiences.sign(new com.nimbusds.jose.crypto.ECDSASigner(key));
        assertThrows(
                IllegalArgumentException.class,
                () -> ClientAssertions.verify(
                        manyAudiences.serialize(), key.toPublicJWK(), verification(AssertionOperation.STATUS, null)));
        assertThrows(
                IllegalArgumentException.class, () -> ClientAssertions.decodeUnverified(manyAudiences.serialize()));
    }

    @Test
    void reportsRemainingLifecycleAndConfigurationDefects() {
        // A lifecycle Problem carries owner_action_required only as "true".
        assertTrue(paths(AepValidation.problemDetails(new ProblemDetails(
                        "urn:aep:error:verification_pending",
                        "Verification pending",
                        403,
                        null,
                        null,
                        "verification_pending",
                        "false",
                        null,
                        null)))
                .contains("$.owner_action_required"));

        // An advertised API-key header name must be an HTTP field name.
        InspectDocument.GrantTypeConfig config =
                new InspectDocument.GrantTypeConfig(null, null, List.of("x api key"), null, null, "true", null, null);
        InspectDocument document = InspectDocument.builder()
                .version(Aep.VERSION)
                .bindings(new InspectDocument.Bindings(List.of("http")))
                .commands(new InspectDocument.Commands(
                        List.of("inspect", "grant", "revoke"), List.of("api-key"), Map.of("api-key", config)))
                .core(new InspectDocument.Core(List.of("EdDSA", "ES256")))
                .http(new InspectDocument.Http("/aep/", null))
                .identity(new InspectDocument.Identity(List.of("did:web")))
                .service(new InspectDocument.Service("did:web:service.example"))
                .build();
        assertTrue(paths(AepValidation.inspectDocument(document))
                .contains("$.commands.grant_types_config.api-key.header_names[0]"));

        // An OpenAPI reference that is present but not a URI reference is reported once.
        InspectDocument openapi = InspectDocument.builder()
                .version(Aep.VERSION)
                .bindings(new InspectDocument.Bindings(List.of("http")))
                .commands(new InspectDocument.Commands(List.of("inspect"), List.of(), Map.of()))
                .core(new InspectDocument.Core(List.of("EdDSA", "ES256")))
                .http(new InspectDocument.Http(
                        "/aep/", new InspectDocument.OpenApi("not a URI", new InspectDocument.PathMatching("strict"))))
                .identity(new InspectDocument.Identity(List.of("did:web")))
                .service(new InspectDocument.Service("did:web:service.example"))
                .build();
        assertEquals(List.of("$.http.openapi.url"), paths(AepValidation.inspectDocument(openapi)));

        // An absent path_matching is reported through the same path as an invalid one.
        InspectDocument noMatching = InspectDocument.builder()
                .version(Aep.VERSION)
                .bindings(new InspectDocument.Bindings(List.of("http")))
                .commands(new InspectDocument.Commands(List.of("inspect"), List.of(), Map.of()))
                .core(new InspectDocument.Core(List.of("EdDSA", "ES256")))
                .http(new InspectDocument.Http("/aep/", new InspectDocument.OpenApi("/openapi.json", null)))
                .identity(new InspectDocument.Identity(List.of("did:web")))
                .service(new InspectDocument.Service("did:web:service.example"))
                .build();
        assertEquals(
                List.of("$.http.openapi.path_matching.trailing_slash"),
                paths(AepValidation.inspectDocument(noMatching)));
    }
}
