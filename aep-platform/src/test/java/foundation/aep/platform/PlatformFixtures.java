package foundation.aep.platform;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import foundation.aep.core.AssertionOperation;
import foundation.aep.core.ClientAssertionClaims;
import foundation.aep.core.ClientAssertions;
import foundation.aep.core.ManagedAgentStatus;
import foundation.aep.core.PlatformAgentIdentity;
import foundation.aep.core.PlatformDiscoveryDocument;
import foundation.aep.core.PlatformProvisionRequest;
import foundation.aep.core.PlatformSignRequest;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.atomic.AtomicInteger;

/** Shared construction helpers for the AEP Platform tests. */
final class PlatformFixtures {
    static final Instant NOW = Instant.parse("2026-07-06T12:00:00Z");
    static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    static final String SERVICE_DID = "did:web:api.service.example";
    static final String OTHER_SERVICE_DID = "did:web:billing.service.example";
    static final String DID_HOST = "p.example";
    static final String DID_PREFIX = "a";
    static final String DID_URL_TEMPLATE = "https://p.example/a/{agent_did_id}/did.json";
    static final String PRINCIPAL = "principal-1";
    static final String JWT_ID = "assertion-1";
    static final String PROVISION_KEY = "provision";

    private PlatformFixtures() {}

    static PlatformDiscoveryDocument discovery(boolean hostedVerification) {
        return discovery(hostedVerification, DID_URL_TEMPLATE, "300");
    }

    static PlatformDiscoveryDocument discovery(
            boolean hostedVerification, String didUrlTemplate, String defaultLifetimeSeconds) {
        return new PlatformDiscoveryDocument(
                "1.0",
                new PlatformDiscoveryDocument.Endpoints(
                        hostedVerification ? "/v1/aep/verifications" : null,
                        "/v1/aep/agent-identities/{agent_identity_id}",
                        "/v1/aep/agent-identities",
                        "/v1/aep/agent-identities",
                        "/v1/aep/agent-identities/{agent_identity_id}/sign"),
                new PlatformDiscoveryDocument.Http("/v1/aep"),
                new PlatformDiscoveryDocument.Identity(List.of("did:web"), didUrlTemplate),
                new PlatformDiscoveryDocument.Platform("did:web:p.example", hostedVerification, "Example Platform"),
                new PlatformDiscoveryDocument.Signing(List.of("ES256"), defaultLifetimeSeconds));
    }

    static AepPlatform.Builder builder(PlatformAuthorizer authorizer, Keys keys, boolean hostedVerification) {
        return builder(discovery(hostedVerification), authorizer, keys, resolver(true));
    }

    static AepPlatform.Builder builder(
            PlatformDiscoveryDocument discovery,
            PlatformAuthorizer authorizer,
            Keys keys,
            PlatformServiceDidResolver resolver) {
        AtomicInteger identity = new AtomicInteger();
        AtomicInteger did = new AtomicInteger();
        return AepPlatform.builder(discovery, DID_HOST, authorizer, keys, resolver)
                .clock(CLOCK)
                .didPathPrefix(DID_PREFIX)
                .identityIdSupplier(() -> Integer.toString(identity.incrementAndGet()))
                .agentDidIdSupplier(() -> "opaque" + did.incrementAndGet())
                .replayStore(PlatformReplayStore.inMemory());
    }

    static AepPlatform platform(PlatformAuthorizer authorizer, Keys keys, boolean hostedVerification) {
        return builder(authorizer, keys, hostedVerification).build();
    }

    static PlatformAuthorizer allow() {
        return (request, context) -> completed(true);
    }

    static PlatformServiceDidResolver resolver(boolean resolved) {
        return (serviceDid, context) -> completed(resolved);
    }

    static PlatformRequestContext context(String key) {
        return new PlatformRequestContext(PRINCIPAL, key, NOW, Map.of());
    }

    static PlatformAgentIdentity provision(AepPlatform platform, String serviceDid, String key) {
        return (PlatformAgentIdentity) platform.provision(new PlatformProvisionRequest(serviceDid), context(key))
                .toCompletableFuture()
                .join()
                .body();
    }

    static PlatformSignRequest signRequest(String lifetimeSeconds) {
        return new PlatformSignRequest(JWT_ID, lifetimeSeconds, AssertionOperation.ENROLL, null, null, SERVICE_DID);
    }

    static PlatformIdentityRecord record(ManagedAgentStatus status) {
        return PlatformIdentityRecord.builder()
                .agentDid("did:web:p.example:a:opaque")
                .agentDidId("opaque")
                .agentIdentityId("pai_identity")
                .createdAt(NOW)
                .didDocumentUrl("https://p.example/a/opaque/did.json")
                .keyId("did:web:p.example:a:opaque")
                .principal(PRINCIPAL)
                .serviceDid(SERVICE_DID)
                .signingAlgorithms(List.of("ES256"))
                .status(status)
                .updatedAt(NOW)
                .build();
    }

    static <T> CompletionStage<T> completed(T value) {
        return CompletableFuture.completedFuture(value);
    }

    /** A key store backed by one P-256 key, with hooks for the failure paths under test. */
    static class Keys implements PlatformKeyStore {
        final ECKey key;
        final AtomicInteger created = new AtomicInteger();
        String keyIdSuffix = "";

        Keys() throws JOSEException {
            key = new ECKeyGenerator(Curve.P_256).keyID("platform-key").generate();
        }

        @Override
        public CompletionStage<Void> create(PlatformIdentityRecord identity, PlatformRequestContext context) {
            created.incrementAndGet();
            return completed(null);
        }

        @Override
        public CompletionStage<PlatformDidVerificationMethod> didVerificationMethod(
                PlatformIdentityRecord identity, PlatformRequestContext context) {
            return completed(new PlatformDidVerificationMethod(
                    identity.agentDid(), identity.agentDid(), key.toPublicJWK().toJSONObject(), "JsonWebKey2020"));
        }

        @Override
        public CompletionStage<String> sign(
                PlatformIdentityRecord identity, ClientAssertionClaims claims, PlatformRequestContext context) {
            return completed(ClientAssertions.sign(claims, key, identity.keyId() + keyIdSuffix));
        }

        @Override
        public CompletionStage<JWK> verificationKey(PlatformIdentityRecord identity, PlatformRequestContext context) {
            return completed(key.toPublicJWK());
        }
    }
}
