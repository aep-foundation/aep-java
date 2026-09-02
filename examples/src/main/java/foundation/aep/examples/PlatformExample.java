package foundation.aep.examples;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import foundation.aep.core.Aep;
import foundation.aep.core.AssertionOperation;
import foundation.aep.core.ClientAssertionClaims;
import foundation.aep.core.ClientAssertionVerification;
import foundation.aep.core.ClientAssertions;
import foundation.aep.core.PlatformAgentIdentity;
import foundation.aep.core.PlatformDiscoveryDocument;
import foundation.aep.core.PlatformProvisionRequest;
import foundation.aep.core.PlatformSignRequest;
import foundation.aep.core.PlatformSignResponses;
import foundation.aep.platform.AepPlatform;
import foundation.aep.platform.PlatformDidVerificationMethod;
import foundation.aep.platform.PlatformIdentityRecord;
import foundation.aep.platform.PlatformKeyStore;
import foundation.aep.platform.PlatformReplayStore;
import foundation.aep.platform.PlatformRequestContext;
import foundation.aep.platform.PlatformResponse;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ConcurrentHashMap;

public final class PlatformExample {
    private static final String SERVICE_DID = "did:web:service.example";

    private PlatformExample() {}

    public static void main(String[] arguments) {
        ExampleKeyStore keyStore = new ExampleKeyStore();
        AepPlatform platform = AepPlatform.builder(
                        discovery(),
                        "platform.example",
                        (request, context) -> CompletableFuture.completedFuture(true),
                        keyStore,
                        (serviceDid, context) -> CompletableFuture.completedFuture(true))
                .replayStore(PlatformReplayStore.inMemory())
                .build();
        PlatformRequestContext context = new PlatformRequestContext("example-user", "provision-1");

        PlatformResponse<PlatformAgentIdentity> provisioned = platform.provision(
                        new PlatformProvisionRequest(SERVICE_DID), context)
                .toCompletableFuture()
                .join();
        PlatformAgentIdentity identity = body(provisioned, "provision");
        System.out.println("Provisioned Agent DID: " + identity.agentDid()); // NOPMD - Example output.

        PlatformSignRequest request = new PlatformSignRequest(
                "example-assertion", "300", AssertionOperation.ENROLL, Map.of("request", "example"), null, SERVICE_DID);
        PlatformResponse<PlatformSignResponses.Response> signed = platform.sign(
                        identity.agentIdentityId(), request, new PlatformRequestContext("example-user", "sign-1"))
                .toCompletableFuture()
                .join();
        PlatformSignResponses.Response signResponse = body(signed, "sign");
        if (!(signResponse instanceof PlatformSignResponses.Completed completed)) {
            throw new IllegalStateException("The example Platform returned pending signing.");
        }
        ClientAssertionClaims verified = ClientAssertions.verify(
                completed.clientAssertion(),
                keyStore.publicKey(identity.agentIdentityId()),
                ClientAssertionVerification.builder(SERVICE_DID, identity.agentDid(), AssertionOperation.ENROLL)
                        .build());
        System.out.println( // NOPMD - Example output.
                "Signed assertion operation: " + verified.operation().value());
    }

    private static PlatformDiscoveryDocument discovery() {
        return new PlatformDiscoveryDocument(
                Aep.VERSION,
                new PlatformDiscoveryDocument.Endpoints(
                        null,
                        "/v1/aep/agent-identities/{agent_identity_id}",
                        "/v1/aep/agent-identities",
                        "/v1/aep/agent-identities",
                        "/v1/aep/agent-identities/{agent_identity_id}/sign"),
                new PlatformDiscoveryDocument.Http("/v1/aep/"),
                new PlatformDiscoveryDocument.Identity(
                        List.of(Aep.IDENTITY_METHOD_DID_WEB),
                        "https://platform.example/agents/{agent_did_id}/did.json"),
                new PlatformDiscoveryDocument.Platform("did:web:platform.example", false, "Example Platform"),
                new PlatformDiscoveryDocument.Signing(List.of("ES256"), "300"));
    }

    private static <T> T body(PlatformResponse<T> response, String operation) {
        if (response.status() < 200 || response.status() >= 300 || response.body() == null) {
            throw new IllegalStateException("The example Platform could not " + operation + '.');
        }
        return response.body();
    }

    private static final class ExampleKeyStore implements PlatformKeyStore {
        private final Map<String, ECKey> keys = new ConcurrentHashMap<>();

        @Override
        public CompletionStage<Void> create(PlatformIdentityRecord identity, PlatformRequestContext context) {
            ECKey key = generateKey(identity.keyId());
            if (keys.putIfAbsent(identity.agentIdentityId(), key) != null) {
                return CompletableFuture.failedFuture(
                        new IllegalStateException("The example identity key already exists."));
            }
            return CompletableFuture.completedFuture(null);
        }

        @Override
        public CompletionStage<PlatformDidVerificationMethod> didVerificationMethod(
                PlatformIdentityRecord identity, PlatformRequestContext context) {
            return CompletableFuture.completedFuture(new PlatformDidVerificationMethod(
                    identity.agentDid(),
                    identity.keyId(),
                    key(identity.agentIdentityId()).toPublicJWK().toJSONObject(),
                    "JsonWebKey2020"));
        }

        @Override
        public CompletionStage<String> sign(
                PlatformIdentityRecord identity, ClientAssertionClaims claims, PlatformRequestContext context) {
            return CompletableFuture.completedFuture(
                    ClientAssertions.sign(claims, key(identity.agentIdentityId()), identity.keyId()));
        }

        @Override
        public CompletionStage<JWK> verificationKey(PlatformIdentityRecord identity, PlatformRequestContext context) {
            return CompletableFuture.completedFuture(publicKey(identity.agentIdentityId()));
        }

        JWK publicKey(String identityId) {
            return key(identityId).toPublicJWK();
        }

        private ECKey key(String identityId) {
            ECKey key = keys.get(identityId);
            if (key == null) throw new IllegalStateException("The example identity key is unavailable.");
            return key;
        }

        private static ECKey generateKey(String id) {
            try {
                return new ECKeyGenerator(Curve.P_256).keyID(id).generate();
            } catch (JOSEException exception) {
                throw new IllegalStateException("Unable to generate the example signing key.", exception);
            }
        }
    }
}
