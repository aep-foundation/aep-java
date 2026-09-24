package foundation.aep.platform;

import static foundation.aep.platform.PlatformFixtures.DID_URL_TEMPLATE;
import static foundation.aep.platform.PlatformFixtures.JWT_ID;
import static foundation.aep.platform.PlatformFixtures.NOW;
import static foundation.aep.platform.PlatformFixtures.OTHER_SERVICE_DID;
import static foundation.aep.platform.PlatformFixtures.PROVISION_KEY;
import static foundation.aep.platform.PlatformFixtures.SERVICE_DID;
import static foundation.aep.platform.PlatformFixtures.allow;
import static foundation.aep.platform.PlatformFixtures.builder;
import static foundation.aep.platform.PlatformFixtures.completed;
import static foundation.aep.platform.PlatformFixtures.context;
import static foundation.aep.platform.PlatformFixtures.discovery;
import static foundation.aep.platform.PlatformFixtures.platform;
import static foundation.aep.platform.PlatformFixtures.provision;
import static foundation.aep.platform.PlatformFixtures.resolver;
import static foundation.aep.platform.PlatformFixtures.signRequest;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import foundation.aep.core.Aep;
import foundation.aep.core.AssertionOperation;
import foundation.aep.core.ManagedAgentStatus;
import foundation.aep.core.PlatformAgentIdentity;
import foundation.aep.core.PlatformLifecycleRequest;
import foundation.aep.core.PlatformProvisionRequest;
import foundation.aep.core.PlatformSignRequest;
import foundation.aep.core.PlatformSignResponses;
import foundation.aep.core.PlatformVerificationRequest;
import foundation.aep.core.ProblemDetails;
import java.time.Duration;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

/** Requirement-level checks for draft-kavian-aep-platform-hosted-identity-01. */
final class PlatformConformanceTest {
    private static final String SIGN_KEY = "sign-1";
    private static final String VERIFY_KEY = "verify-1";
    private static final String NOT_RECOGNIZED = "not_recognized";
    private static final String ISSUED_AT = "2026-07-06T12:00:00Z";
    private static final String RETRY_AFTER = "Retry-After";

    @Test
    void authorizesEveryRetryWithoutRepeatingCompletedOperations() throws JOSEException {
        var allowed = new AtomicBoolean(true);
        var checks = new AtomicInteger();
        var keys = new PlatformFixtures.Keys();
        var platform = builder(
                        (request, context) -> {
                            checks.incrementAndGet();
                            return completed(allowed.get());
                        },
                        keys,
                        true)
                .build();
        var provisionRequest = new PlatformProvisionRequest(SERVICE_DID);
        var provisioned = platform.provision(provisionRequest, context(PROVISION_KEY))
                .toCompletableFuture()
                .join();
        var identity = provisioned.body();
        var signed = platform.sign(identity.agentIdentityId(), signRequest(null), context(SIGN_KEY))
                .toCompletableFuture()
                .join();
        var assertion = ((PlatformSignResponses.Completed) signed.body()).clientAssertion();
        var verification = new PlatformVerificationRequest(assertion, AssertionOperation.ENROLL, null, SERVICE_DID);
        var verified = platform.verify(verification, context(VERIFY_KEY))
                .toCompletableFuture()
                .join();
        assertTrue(verified.body().verified());

        allowed.set(false);
        assertEquals(
                404,
                platform.provision(provisionRequest, context(PROVISION_KEY))
                        .toCompletableFuture()
                        .join()
                        .status());
        assertEquals(
                404,
                platform.sign(identity.agentIdentityId(), signRequest(null), context(SIGN_KEY))
                        .toCompletableFuture()
                        .join()
                        .status());
        assertFalse(platform.verify(verification, context(VERIFY_KEY))
                .toCompletableFuture()
                .join()
                .body()
                .verified());
        assertEquals(6, checks.get());

        allowed.set(true);
        assertEquals(
                provisioned,
                platform.provision(provisionRequest, context(PROVISION_KEY))
                        .toCompletableFuture()
                        .join());
        assertEquals(
                signed,
                platform.sign(identity.agentIdentityId(), signRequest(null), context(SIGN_KEY))
                        .toCompletableFuture()
                        .join());
        assertEquals(
                verified,
                platform.verify(verification, context(VERIFY_KEY))
                        .toCompletableFuture()
                        .join());
        assertEquals(9, checks.get());
        assertEquals(1, keys.created.get());
        assertFalse(platform.verify(verification, context("another-verification"))
                .toCompletableFuture()
                .join()
                .body()
                .verified());
    }

    @Test
    void deniedProvisionDoesNotReserveTheIdempotencyKey() throws JOSEException {
        var allowed = new AtomicBoolean(false);
        var platform = platform((request, context) -> completed(allowed.get()), new PlatformFixtures.Keys(), true);
        var request = new PlatformProvisionRequest(SERVICE_DID);
        assertEquals(
                404,
                platform.provision(request, context(PROVISION_KEY))
                        .toCompletableFuture()
                        .join()
                        .status());
        allowed.set(true);
        assertEquals(
                200,
                platform.provision(request, context(PROVISION_KEY))
                        .toCompletableFuture()
                        .join()
                        .status());
    }

    @Test
    void authorizesInFlightRetriesAndPreservesPendingResponses() throws JOSEException {
        var allowed = new AtomicBoolean(true);
        var calls = new AtomicInteger();
        var result = new CompletableFuture<PlatformResponse<PlatformSignResponses.Response>>();
        var platform = builder((request, context) -> completed(allowed.get()), new PlatformFixtures.Keys(), true)
                .signHandler((identity, request, context) -> {
                    calls.incrementAndGet();
                    return result.thenApply(Optional::of);
                })
                .build();
        var identity = provision(platform, SERVICE_DID, PROVISION_KEY);
        var first = platform.sign(identity.agentIdentityId(), signRequest(null), context(SIGN_KEY))
                .toCompletableFuture();
        allowed.set(false);
        assertEquals(
                404,
                platform.sign(identity.agentIdentityId(), signRequest(null), context(SIGN_KEY))
                        .toCompletableFuture()
                        .join()
                        .status());
        allowed.set(true);
        var retry = platform.sign(identity.agentIdentityId(), signRequest(null), context(SIGN_KEY))
                .toCompletableFuture();
        assertFalse(retry.isDone());
        result.complete(pending(Map.of()));
        assertEquals(202, first.join().status());
        assertEquals(first.join(), retry.join());
        assertEquals(
                first.join(),
                platform.sign(identity.agentIdentityId(), signRequest(null), context(SIGN_KEY))
                        .toCompletableFuture()
                        .join());
        assertEquals(1, calls.get());
    }

    @Test
    void missingAssertionBindingsReturnUnrecognized() throws JOSEException {
        var keys = new PlatformFixtures.Keys();
        var platform = platform(allow(), keys, true);
        var identity = provision(platform, SERVICE_DID, PROVISION_KEY);
        for (String missing : List.of("iss", "sub", "kid")) {
            var claims = new JWTClaimsSet.Builder()
                    .issuer(missing.equals("iss") ? null : identity.agentDid())
                    .subject(missing.equals("sub") ? null : identity.agentDid())
                    .audience(SERVICE_DID)
                    .claim("op", "enroll")
                    .issueTime(Date.from(NOW))
                    .expirationTime(Date.from(NOW.plusSeconds(60)))
                    .jwtID("missing-" + missing)
                    .build();
            var jwt = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.ES256)
                            .type(JOSEObjectType.JWT)
                            .keyID(missing.equals("kid") ? null : identity.agentDid())
                            .build(),
                    claims);
            jwt.sign(new ECDSASigner(keys.key));
            var response = platform.verify(
                            new PlatformVerificationRequest(
                                    jwt.serialize(), AssertionOperation.ENROLL, null, SERVICE_DID),
                            context("missing-" + missing))
                    .toCompletableFuture()
                    .join();
            assertEquals(200, response.status());
            assertFalse(response.body().verified());
            assertEquals(NOT_RECOGNIZED, response.body().reason());
        }
    }

    /** PLT-DISC-012, PLT-DISC-013, PLT-DISC-015: freshness plus validators on Discovery. */
    @Test
    void discoveryCarriesFreshnessAndCacheValidators() throws JOSEException {
        var headers = platform(allow(), new PlatformFixtures.Keys(), false)
                .discovery()
                .headers();

        assertEquals(List.of("max-age=300"), headers.get("Cache-Control"));
        assertTrue(headers.get("ETag").get(0).startsWith("\"sha256:"));
        assertEquals(List.of("Mon, 06 Jul 2026 12:00:00 GMT"), headers.get("Last-Modified"));
    }

    /** PLT-DISC-012: the validator is derived from the document, so unlike documents differ. */
    @Test
    void discoveryEntityTagTracksDocumentContent() throws JOSEException {
        PlatformFixtures.Keys keys = new PlatformFixtures.Keys();
        String first =
                platform(allow(), keys, false).discovery().headers().get("ETag").get(0);
        String same =
                platform(allow(), keys, false).discovery().headers().get("ETag").get(0);
        String other = builder(discovery(false, DID_URL_TEMPLATE, "120"), allow(), keys, resolver(true))
                .build()
                .discovery()
                .headers()
                .get("ETag")
                .get(0);

        assertEquals(first, same);
        assertNotEquals(first, other);
    }

    /** PLT-DID-005, PLT-DISC-006: the advertised template must be where did:web resolution lands. */
    @Test
    void rejectsDidUrlTemplateThatDoesNotMatchDidWebResolution() throws JOSEException {
        PlatformFixtures.Keys keys = new PlatformFixtures.Keys();
        var mismatched = builder(
                discovery(false, "https://p.example/b/{agent_did_id}/did.json", "300"), allow(), keys, resolver(true));
        var offHost = builder(
                discovery(false, "https://other.example/a/{agent_did_id}/did.json", "300"),
                allow(),
                keys,
                resolver(true));

        assertTrue(assertThrows(IllegalArgumentException.class, mismatched::build)
                .getMessage()
                .contains("did_url_template renders"));
        assertThrows(IllegalArgumentException.class, offHost::build);
    }

    /** PLT-LIFE-002, PLT-SIGN-007: a policy hook may narrow the active-only floor, never widen it. */
    @Test
    void refusesDelegatedSigningOutsideTheActiveState() throws JOSEException {
        AepPlatform platform = builder(allow(), new PlatformFixtures.Keys(), false)
                .lifecyclePolicy(permissive())
                .build();
        PlatformAgentIdentity identity = provision(platform, SERVICE_DID, PROVISION_KEY);

        assertEquals("identity_suspended", refusedSign(platform, identity, ManagedAgentStatus.SUSPENDED));
        assertEquals("identity_suspended", refusedSign(platform, identity, ManagedAgentStatus.REVOKED));
        assertEquals("identity_terminated", refusedSign(platform, identity, ManagedAgentStatus.TERMINATED));
    }

    /** PLT-VER-004, PLT-LIFE-002: hosted verification checks the current lifecycle state too. */
    @Test
    void refusesHostedVerificationOutsideTheActiveState() throws JOSEException {
        PlatformFixtures.Keys keys = new PlatformFixtures.Keys();
        AepPlatform platform =
                builder(allow(), keys, true).lifecyclePolicy(permissive()).build();
        PlatformAgentIdentity identity = provision(platform, SERVICE_DID, PROVISION_KEY);
        String assertion = signedAssertion(platform, identity);
        platform.updateIdentity(
                        identity.agentIdentityId(),
                        new PlatformLifecycleRequest(ManagedAgentStatus.SUSPENDED),
                        context(null))
                .toCompletableFuture()
                .join();

        var response = platform.verify(
                        new PlatformVerificationRequest(assertion, AssertionOperation.ENROLL, null, SERVICE_DID),
                        context(VERIFY_KEY))
                .toCompletableFuture()
                .join()
                .body();

        assertFalse(response.verified());
        assertEquals(NOT_RECOGNIZED, response.reason());
        assertEquals(null, response.status());
    }

    /** PLT-SIGN-022: a Platform-hosted kid is the Agent DID itself, with no method fragment. */
    @Test
    void rejectsAssertionsWhoseKeyIdCarriesAVerificationMethodFragment() throws JOSEException {
        PlatformFixtures.Keys keys = new PlatformFixtures.Keys();
        keys.keyIdSuffix = "#key-1";
        AepPlatform platform = platform(allow(), keys, true);
        PlatformAgentIdentity identity = provision(platform, SERVICE_DID, PROVISION_KEY);
        String assertion = signedAssertion(platform, identity);

        var response = platform.verify(
                        new PlatformVerificationRequest(assertion, AssertionOperation.ENROLL, null, SERVICE_DID),
                        context(VERIFY_KEY))
                .toCompletableFuture()
                .join()
                .body();

        assertFalse(response.verified());
        assertEquals(NOT_RECOGNIZED, response.reason());
    }

    /** PLT-VER-008, PLT-VER-010: an unrecognized assertion discloses nothing about the identity. */
    @Test
    void reportsUnrecognizedForAssertionsItCannotTieToAnIdentity() throws JOSEException {
        PlatformFixtures.Keys keys = new PlatformFixtures.Keys();
        AepPlatform platform = platform(allow(), keys, true);
        PlatformAgentIdentity identity = provision(platform, SERVICE_DID, PROVISION_KEY);
        String assertion = signedAssertion(platform, identity);

        assertFalse(verified(platform, "not-a-jwt", SERVICE_DID, "v-garbage"));
        assertFalse(verified(platform, assertion, OTHER_SERVICE_DID, "v-service"));
        assertTrue(verified(platform, assertion, SERVICE_DID, "v-good"));
    }

    /** PLT-SIGN-017: the HTTP Retry-After header stays off this contract, success or problem. */
    @Test
    void rejectsSignHandlerResponsesCarryingRetryAfter() throws JOSEException {
        assertThrows(
                CompletionException.class,
                () -> handledSign(pending(Map.of(RETRY_AFTER, List.of("5")))),
                "pending response");
        assertThrows(
                CompletionException.class,
                () -> handledSign(pending(Map.of("retry-after", List.of("5")))),
                "header names are case-insensitive");
        assertThrows(
                CompletionException.class,
                () -> handledSign(new PlatformResponse<>(
                        503,
                        Aep.PROBLEM_MEDIA_TYPE,
                        null,
                        ProblemDetails.of("temporarily_unavailable", "Try later.", 503),
                        Map.of(RETRY_AFTER, List.of("5")))),
                "problem response");
        assertEquals(202, handledSign(pending(Map.of())).status());
    }

    /** PLT-SIGN-010: a handler-minted validity window is bounded like a Platform-minted one. */
    @Test
    void boundsSignHandlerAssertionLifetimes() throws JOSEException {
        assertEquals(
                200,
                handledSign(completedSign(ISSUED_AT, "2026-07-06T12:05:00Z")).status());
        assertEquals(
                200,
                handledSign(completedSign(ISSUED_AT, "2026-07-06T12:05:00+00:00"))
                        .status());
        assertThrows(
                CompletionException.class,
                () -> handledSign(completedSign(ISSUED_AT, "2026-07-06T12:05:01Z")),
                "301 seconds exceeds the maximum");
        assertThrows(
                CompletionException.class,
                () -> handledSign(completedSign(ISSUED_AT, ISSUED_AT)),
                "a zero-length window never validates");
        assertThrows(
                CompletionException.class,
                () -> handledSign(completedSign("2026-07-06T12:05:00Z", ISSUED_AT)),
                "expiry must follow issuance");
        assertThrows(
                CompletionException.class,
                () -> handledSign(completedSign("whenever", ISSUED_AT)),
                "an unparseable instant is not a bounded window");
    }

    /** PLT-SIGN-010, PLT-SIGN-011: a shorter configured maximum also binds the handler path. */
    @Test
    void appliesTheConfiguredMaximumToBothSigningPaths() throws JOSEException {
        PlatformFixtures.Keys keys = new PlatformFixtures.Keys();
        AepPlatform platform = builder(discovery(false, DID_URL_TEMPLATE, "60"), allow(), keys, resolver(true))
                .maximumLifetime(Duration.ofSeconds(60))
                .build();
        PlatformAgentIdentity identity = provision(platform, SERVICE_DID, PROVISION_KEY);

        assertEquals(
                400,
                platform.sign(identity.agentIdentityId(), signRequest("61"), context(SIGN_KEY))
                        .toCompletableFuture()
                        .join()
                        .status());
        assertEquals(
                200,
                platform.sign(identity.agentIdentityId(), signRequest("60"), context("sign-2"))
                        .toCompletableFuture()
                        .join()
                        .status());
    }

    /** PLT-SIGN-008: lifetime_seconds is a canonical decimal string within 1..300. */
    @Test
    void rejectsNonCanonicalLifetimeEncodings() throws JOSEException {
        AepPlatform platform = platform(allow(), new PlatformFixtures.Keys(), false);
        PlatformAgentIdentity identity = provision(platform, SERVICE_DID, PROVISION_KEY);

        assertEquals(400, signStatus(platform, identity, "+60", "s1"));
        assertEquals(400, signStatus(platform, identity, "060", "s2"));
        assertEquals(400, signStatus(platform, identity, "0", "s3"));
        assertEquals(400, signStatus(platform, identity, "301", "s4"));
        assertEquals(200, signStatus(platform, identity, "300", "s5"));
    }

    /** PLT-IDP-001, PLT-IDP-003: every replayable operation needs a key and a principal. */
    @Test
    void requiresAnIdempotencyKeyAndPrincipalOnReplayableOperations() throws JOSEException {
        PlatformFixtures.Keys keys = new PlatformFixtures.Keys();
        AepPlatform platform = platform(allow(), keys, true);
        PlatformAgentIdentity identity = provision(platform, SERVICE_DID, PROVISION_KEY);
        PlatformRequestContext anonymous = new PlatformRequestContext(" ", PROVISION_KEY, NOW, Map.of());

        assertEquals(
                400,
                platform.provision(new foundation.aep.core.PlatformProvisionRequest(SERVICE_DID), context(null))
                        .toCompletableFuture()
                        .join()
                        .status());
        assertEquals(
                400,
                platform.sign(identity.agentIdentityId(), signRequest(null), anonymous)
                        .toCompletableFuture()
                        .join()
                        .status());
        assertEquals(
                400,
                platform.verify(
                                new PlatformVerificationRequest("token", AssertionOperation.ENROLL, null, SERVICE_DID),
                                context("  "))
                        .toCompletableFuture()
                        .join()
                        .status());
    }

    /** PLT-IDP-009: the same key for different material is a conflict, not a silent replay. */
    @Test
    void reportsConflictWhenAKeyIsReusedForDifferentMaterial() throws JOSEException {
        AepPlatform platform = platform(allow(), new PlatformFixtures.Keys(), false);
        PlatformAgentIdentity identity = provision(platform, SERVICE_DID, PROVISION_KEY);

        var conflict = platform.sign(identity.agentIdentityId(), signRequest("60"), context(SIGN_KEY))
                .thenCompose(
                        ignored -> platform.sign(identity.agentIdentityId(), signRequest("120"), context(SIGN_KEY)))
                .toCompletableFuture()
                .join();

        assertEquals(409, conflict.status());
        assertEquals("idempotency_conflict", conflict.problem().code());
    }

    /** PLT-VER-001: hosted verification answers only where the Platform advertises it. */
    @Test
    void refusesHostedVerificationWhenItIsNotAdvertised() throws JOSEException {
        AepPlatform platform = platform(allow(), new PlatformFixtures.Keys(), false);

        var response = platform.verify(
                        new PlatformVerificationRequest("token", AssertionOperation.ENROLL, null, SERVICE_DID),
                        context(VERIFY_KEY))
                .toCompletableFuture()
                .join();

        assertEquals(404, response.status());
        assertEquals(NOT_RECOGNIZED, response.problem().code());
    }

    /** PLT-VER-001: the advertised capability and the advertised endpoint travel together. */
    @Test
    void rejectsPartialHostedVerificationConfiguration() throws JOSEException {
        PlatformFixtures.Keys keys = new PlatformFixtures.Keys();
        var withoutReplayStore = AepPlatform.builder(discovery(true), "p.example", allow(), keys, resolver(true))
                .didPathPrefix("a");
        var capabilityOnly = new foundation.aep.core.PlatformDiscoveryDocument(
                "1.0",
                new foundation.aep.core.PlatformDiscoveryDocument.Endpoints(
                        null,
                        "/v1/aep/agent-identities/{agent_identity_id}",
                        "/v1/aep/agent-identities",
                        "/v1/aep/agent-identities",
                        "/v1/aep/agent-identities/{agent_identity_id}/sign"),
                new foundation.aep.core.PlatformDiscoveryDocument.Http("/v1/aep"),
                new foundation.aep.core.PlatformDiscoveryDocument.Identity(List.of("did:web"), DID_URL_TEMPLATE),
                new foundation.aep.core.PlatformDiscoveryDocument.Platform("did:web:p.example", true, "Example"),
                new foundation.aep.core.PlatformDiscoveryDocument.Signing(List.of("ES256"), "300"));

        assertThrows(IllegalArgumentException.class, withoutReplayStore::build);
        var endpointMismatch = builder(capabilityOnly, allow(), keys, resolver(true));
        assertThrows(IllegalArgumentException.class, endpointMismatch::build);
    }

    /** PLT-VER-006, PLT-VER-007: resource travels with authenticate and with nothing else. */
    @Test
    void bindsTheProtectedResourceToAuthenticateOnly() throws JOSEException {
        PlatformFixtures.Keys keys = new PlatformFixtures.Keys();
        AepPlatform platform = platform(allow(), keys, true);
        PlatformAgentIdentity identity = provision(platform, SERVICE_DID, PROVISION_KEY);
        PlatformSignRequest request = new PlatformSignRequest(
                JWT_ID, null, AssertionOperation.AUTHENTICATE, null, "https://api.service.example/orders", SERVICE_DID);
        var signed =
                (PlatformSignResponses.Completed) platform.sign(identity.agentIdentityId(), request, context(SIGN_KEY))
                        .toCompletableFuture()
                        .join()
                        .body();

        assertEquals(
                400,
                platform.verify(
                                new PlatformVerificationRequest(
                                        signed.clientAssertion(), AssertionOperation.AUTHENTICATE, null, SERVICE_DID),
                                context("v-missing"))
                        .toCompletableFuture()
                        .join()
                        .status());
        assertFalse(platform.verify(
                        new PlatformVerificationRequest(
                                signed.clientAssertion(),
                                AssertionOperation.AUTHENTICATE,
                                "https://api.service.example/other",
                                SERVICE_DID),
                        context("v-wrong"))
                .toCompletableFuture()
                .join()
                .body()
                .verified());
        assertTrue(platform.verify(
                        new PlatformVerificationRequest(
                                signed.clientAssertion(),
                                AssertionOperation.AUTHENTICATE,
                                "https://api.service.example/orders",
                                SERVICE_DID),
                        context("v-right"))
                .toCompletableFuture()
                .join()
                .body()
                .verified());
    }

    /** PLT-PROV-006, PLT-PROV-007: a syntactic DID that no resolver recognizes is refused. */
    @Test
    void refusesProvisioningForUnresolvableOrMalformedServiceDids() throws JOSEException {
        PlatformFixtures.Keys keys = new PlatformFixtures.Keys();
        AepPlatform unresolvable =
                builder(discovery(false), allow(), keys, resolver(false)).build();
        AepPlatform platform = platform(allow(), keys, false);

        assertEquals(
                400,
                platform.provision(new foundation.aep.core.PlatformProvisionRequest("not-a-did"), context("p1"))
                        .toCompletableFuture()
                        .join()
                        .status());
        assertEquals(
                400,
                unresolvable
                        .provision(new foundation.aep.core.PlatformProvisionRequest(SERVICE_DID), context("p2"))
                        .toCompletableFuture()
                        .join()
                        .status());
        assertEquals(0, keys.created.get());
    }

    /** PLT-PROV-008, PLT-PROV-012: Service-scoped DIDs share only the Platform-controlled prefix. */
    @Test
    void mintsDistinctServiceScopedDidsPerService() throws JOSEException {
        AepPlatform platform = platform(allow(), new PlatformFixtures.Keys(), false);

        PlatformAgentIdentity first = provision(platform, SERVICE_DID, "p1");
        PlatformAgentIdentity second = provision(platform, OTHER_SERVICE_DID, "p2");

        assertNotEquals(first.agentDid(), second.agentDid());
        assertTrue(first.agentDid().startsWith("did:web:p.example:a:"));
        assertTrue(second.agentDid().startsWith("did:web:p.example:a:"));
        assertFalse(first.agentDid().contains("api.service"));
        assertFalse(second.agentDid().contains("billing.service"));
        assertEquals(first.didDocumentUrl(), "https://p.example/a/opaque1/did.json");
    }

    /** PLT-LIFE-007, PLT-LIFE-009: a Platform defines its own transitions and reports refusals. */
    @Test
    void reportsRefusedLifecycleTransitions() throws JOSEException {
        AepPlatform platform = builder(allow(), new PlatformFixtures.Keys(), false)
                .lifecyclePolicy(new PlatformLifecyclePolicy() {
                    @Override
                    public CompletionStage<Boolean> canSign(
                            PlatformIdentityRecord identity, PlatformRequestContext context) {
                        return completed(true);
                    }

                    @Override
                    public CompletionStage<Boolean> canTransition(
                            PlatformIdentityRecord identity,
                            ManagedAgentStatus nextStatus,
                            PlatformRequestContext context) {
                        return completed(false);
                    }

                    @Override
                    public CompletionStage<Boolean> canVerify(
                            PlatformIdentityRecord identity, PlatformRequestContext context) {
                        return completed(true);
                    }
                })
                .build();
        PlatformAgentIdentity identity = provision(platform, SERVICE_DID, PROVISION_KEY);

        var refused = platform.updateIdentity(
                        identity.agentIdentityId(),
                        new PlatformLifecycleRequest(ManagedAgentStatus.SUSPENDED),
                        context(null))
                .toCompletableFuture()
                .join();

        assertEquals(403, refused.status());
        assertEquals("identity_unavailable", refused.problem().code());
    }

    /** PLT-ERR-004, PLT-ERR-005: a denied management operation is a bare 404 with no side effect. */
    @Test
    void deniedOperationsLookLikeMissingOnes() throws JOSEException {
        PlatformFixtures.Keys keys = new PlatformFixtures.Keys();
        AtomicReference<Boolean> authorized = new AtomicReference<>(true);
        AepPlatform platform = platform((request, context) -> completed(authorized.get()), keys, false);
        PlatformAgentIdentity identity = provision(platform, SERVICE_DID, PROVISION_KEY);
        authorized.set(false);

        assertEquals(404, statusOf(platform.getIdentity(identity.agentIdentityId(), context(null))));
        assertEquals(404, statusOf(platform.list(PlatformIdentityListQuery.defaults(), context(null))));
        assertEquals(
                404,
                statusOf(platform.updateIdentity(
                        identity.agentIdentityId(),
                        new PlatformLifecycleRequest(ManagedAgentStatus.SUSPENDED),
                        context(null))));
        assertEquals(404, statusOf(platform.sign(identity.agentIdentityId(), signRequest(null), context(SIGN_KEY))));
        assertEquals(1, keys.created.get());
    }

    /** PLT-LIST-003, PLT-LIST-004, PLT-LIST-006: bounded, deterministic, self-describing pages. */
    @Test
    void pagesIdentitiesDeterministicallyWithinBounds() throws JOSEException {
        AepPlatform platform = platform(allow(), new PlatformFixtures.Keys(), false);
        provision(platform, SERVICE_DID, "p1");
        provision(platform, OTHER_SERVICE_DID, "p2");

        var ascending = platform.list(new PlatformIdentityListQuery(false, 100, 0, null, null), context(null))
                .toCompletableFuture()
                .join()
                .body();
        var descending = platform.list(new PlatformIdentityListQuery(true, 100, 0, null, null), context(null))
                .toCompletableFuture()
                .join()
                .body();
        var scoped = platform.list(new PlatformIdentityListQuery(false, 100, 0, SERVICE_DID, null), context(null))
                .toCompletableFuture()
                .join()
                .body();

        assertEquals("2", ascending.count());
        assertEquals("2", ascending.total());
        assertEquals(
                ascending.data().get(0).agentDid(), descending.data().get(1).agentDid());
        assertEquals("1", scoped.count());
        assertEquals(SERVICE_DID, scoped.data().get(0).serviceDid());
        assertEquals(
                400, statusOf(platform.list(new PlatformIdentityListQuery(false, 0, 0, null, null), context(null))));
        assertEquals(
                400, statusOf(platform.list(new PlatformIdentityListQuery(false, 1, -1, null, null), context(null))));
        assertEquals(
                400, statusOf(platform.list(new PlatformIdentityListQuery(false, 1, 0, "nope", null), context(null))));
    }

    /** PLT-DID-001, PLT-DID-006: DID documents are public, and only for active identities. */
    @Test
    void publishesDidDocumentsForActiveIdentitiesOnly() throws JOSEException {
        AepPlatform platform = platform(allow(), new PlatformFixtures.Keys(), false);
        PlatformAgentIdentity identity = provision(platform, SERVICE_DID, PROVISION_KEY);
        String agentDidId = identity.agentDid().substring(identity.agentDid().lastIndexOf(':') + 1);

        var published =
                platform.getDidDocument(agentDidId, null).toCompletableFuture().join();
        platform.updateIdentity(
                        identity.agentIdentityId(),
                        new PlatformLifecycleRequest(ManagedAgentStatus.REVOKED),
                        context(null))
                .toCompletableFuture()
                .join();

        assertEquals(200, published.status());
        assertEquals(Aep.DID_MEDIA_TYPE, published.contentType());
        assertEquals(identity.agentDid(), published.body().id());
        assertEquals(List.of(identity.agentDid()), published.body().authentication());
        assertEquals(404, statusOf(platform.getDidDocument(agentDidId, null)));
        assertEquals(404, statusOf(platform.getDidDocument(" ", null)));
    }

    /** PLT-SIGN-004: platform_context never reaches the assertion it accompanies. */
    @Test
    void keepsPlatformContextOutOfAssertionClaims() throws JOSEException {
        PlatformFixtures.Keys keys = new PlatformFixtures.Keys();
        AepPlatform platform = platform(allow(), keys, false);
        PlatformAgentIdentity identity = provision(platform, SERVICE_DID, PROVISION_KEY);
        PlatformSignRequest request = new PlatformSignRequest(
                JWT_ID, null, AssertionOperation.ENROLL, Map.of("approval", "opaque"), null, SERVICE_DID);

        var signed =
                (PlatformSignResponses.Completed) platform.sign(identity.agentIdentityId(), request, context(SIGN_KEY))
                        .toCompletableFuture()
                        .join()
                        .body();
        String payload = new String(
                java.util.Base64.getUrlDecoder().decode(signed.clientAssertion().split("\\.")[1]),
                java.nio.charset.StandardCharsets.UTF_8);

        assertEquals("opaque", signed.platformContext().get("approval"));
        assertFalse(payload.contains("platform_context"));
        assertFalse(payload.contains("approval"));
    }

    private static PlatformLifecyclePolicy permissive() {
        return new PlatformLifecyclePolicy() {
            @Override
            public CompletionStage<Boolean> canSign(PlatformIdentityRecord identity, PlatformRequestContext context) {
                return completed(true);
            }

            @Override
            public CompletionStage<Boolean> canTransition(
                    PlatformIdentityRecord identity, ManagedAgentStatus nextStatus, PlatformRequestContext context) {
                return completed(true);
            }

            @Override
            public CompletionStage<Boolean> canVerify(PlatformIdentityRecord identity, PlatformRequestContext context) {
                return completed(true);
            }
        };
    }

    private static String refusedSign(AepPlatform platform, PlatformAgentIdentity identity, ManagedAgentStatus status) {
        platform.updateIdentity(identity.agentIdentityId(), new PlatformLifecycleRequest(status), context(null))
                .toCompletableFuture()
                .join();
        var response = platform.sign(identity.agentIdentityId(), signRequest(null), context("sign-" + status))
                .toCompletableFuture()
                .join();
        assertEquals(403, response.status());
        return response.problem().code();
    }

    private static String signedAssertion(AepPlatform platform, PlatformAgentIdentity identity) {
        return ((PlatformSignResponses.Completed)
                        platform.sign(identity.agentIdentityId(), signRequest(null), context(SIGN_KEY))
                                .toCompletableFuture()
                                .join()
                                .body())
                .clientAssertion();
    }

    private static boolean verified(AepPlatform platform, String assertion, String serviceDid, String key) {
        return platform.verify(
                        new PlatformVerificationRequest(assertion, AssertionOperation.ENROLL, null, serviceDid),
                        context(key))
                .toCompletableFuture()
                .join()
                .body()
                .verified();
    }

    private static int signStatus(
            AepPlatform platform, PlatformAgentIdentity identity, String lifetimeSeconds, String key) {
        return statusOf(platform.sign(identity.agentIdentityId(), signRequest(lifetimeSeconds), context(key)));
    }

    private static int statusOf(CompletionStage<? extends PlatformResponse<?>> stage) {
        return stage.toCompletableFuture().join().status();
    }

    private static PlatformResponse<PlatformSignResponses.Response> pending(Map<String, List<String>> headers) {
        return new PlatformResponse<>(
                202, Aep.MEDIA_TYPE, new PlatformSignResponses.Pending("pending", null, "5"), null, headers);
    }

    private static PlatformResponse<PlatformSignResponses.Response> completedSign(String issuedAt, String expiresAt) {
        return new PlatformResponse<>(
                200,
                Aep.MEDIA_TYPE,
                new PlatformSignResponses.Completed(
                        "completed",
                        "did:web:p.example:a:opaque1",
                        "assertion",
                        expiresAt,
                        issuedAt,
                        JWT_ID,
                        null,
                        SERVICE_DID),
                null,
                Map.of());
    }

    private static PlatformResponse<?> handledSign(PlatformResponse<PlatformSignResponses.Response> handled)
            throws JOSEException {
        AepPlatform platform = builder(allow(), new PlatformFixtures.Keys(), false)
                .signHandler((identity, request, context) -> completed(Optional.of(handled)))
                .build();
        PlatformAgentIdentity identity = provision(platform, SERVICE_DID, PROVISION_KEY);
        return platform.sign(identity.agentIdentityId(), signRequest(null), context(SIGN_KEY))
                .toCompletableFuture()
                .join();
    }
}
