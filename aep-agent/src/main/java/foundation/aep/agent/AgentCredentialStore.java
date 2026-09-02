package foundation.aep.agent;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

public interface AgentCredentialStore {
    CompletionStage<Optional<AgentCredential>> find(String serviceDid, String grantType);

    CompletionStage<Void> save(AgentCredential credential);

    CompletionStage<Void> delete(String serviceDid, String credentialId);

    CompletionStage<Void> deleteGrantType(String serviceDid, String grantType);

    CompletionStage<Void> deleteAll(String serviceDid);

    static AgentCredentialStore inMemory() {
        return new AgentCredentialStore() {
            private final Map<String, AgentCredential> credentials = new LinkedHashMap<>();

            @Override
            public synchronized CompletionStage<Optional<AgentCredential>> find(String serviceDid, String grantType) {
                AgentCredential selected = null;
                for (AgentCredential credential : credentials.values()) {
                    if (credential.serviceDid().equals(serviceDid)
                            && credential.grantType().equals(grantType)) {
                        selected = credential;
                    }
                }
                return CompletableFuture.completedFuture(Optional.ofNullable(selected));
            }

            @Override
            public synchronized CompletionStage<Void> save(AgentCredential credential) {
                String key = key(credential.serviceDid(), credential.credentialId());
                AgentCredential existing = credentials.get(key);
                if (existing != null && !existing.equals(credential)) {
                    return CompletableFuture.failedFuture(
                            new IllegalArgumentException("AEP credential identifier has been reassigned."));
                }
                credentials.put(key, credential);
                return CompletableFuture.completedFuture(null);
            }

            @Override
            public synchronized CompletionStage<Void> delete(String serviceDid, String credentialId) {
                credentials.remove(key(serviceDid, credentialId));
                return CompletableFuture.completedFuture(null);
            }

            @Override
            public synchronized CompletionStage<Void> deleteGrantType(String serviceDid, String grantType) {
                credentials
                        .values()
                        .removeIf(credential -> credential.serviceDid().equals(serviceDid)
                                && credential.grantType().equals(grantType));
                return CompletableFuture.completedFuture(null);
            }

            @Override
            public synchronized CompletionStage<Void> deleteAll(String serviceDid) {
                credentials
                        .values()
                        .removeIf(credential -> credential.serviceDid().equals(serviceDid));
                return CompletableFuture.completedFuture(null);
            }

            private String key(String serviceDid, String credentialId) {
                return serviceDid + '\0' + credentialId;
            }
        };
    }
}
