package foundation.aep.service;

import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.CompletionStage;

public interface ServiceCredentialStore {
    CompletionStage<Optional<ServiceCredentialMatch>> authenticate(
            String grantType, CredentialAuthenticationInput input);

    CompletionStage<Boolean> hasPresentation(String grantType, CredentialAuthenticationInput input);

    CompletionStage<Void> revoke(String agentDid, String grantType, String credentialId, Instant revokedAt);

    CompletionStage<Void> revokeGrantType(String agentDid, String grantType, Instant revokedAt);

    CompletionStage<Void> save(ServiceCredentialRecord record);

    static ServiceCredentialStore inMemory() {
        return new InMemoryServiceCredentialStore();
    }
}
