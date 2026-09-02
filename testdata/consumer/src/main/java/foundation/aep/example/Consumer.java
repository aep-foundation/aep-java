package foundation.aep.example;

import foundation.aep.agent.AepAgent;
import foundation.aep.agent.AgentIdentity;
import foundation.aep.core.AepJson;
import foundation.aep.core.RevokeResponse;
import java.net.URI;
import java.util.concurrent.CompletableFuture;

public final class Consumer {
    private Consumer() {}

    public static void main(String[] args) {
        String json = AepJson.write(new RevokeResponse());
        if (!"{}".equals(json)) {
            throw new IllegalStateException("Unexpected Revoke response JSON: " + json);
        }
        AepJson.parseRevokeResponse(json);

        AepAgent agent = AepAgent.builder()
                .inspectTransport(request -> CompletableFuture.failedFuture(new UnsupportedOperationException()))
                .commandTransport(request -> CompletableFuture.failedFuture(new UnsupportedOperationException()))
                .identityProvider((origin, serviceDid) -> CompletableFuture.completedFuture(
                        new AgentIdentity(
                                "did:web:agent.example",
                                claims -> CompletableFuture.completedFuture("signed-assertion"))))
                .build();
        URI origin = URI.create("https://service.example");
        if (!origin.equals(agent.service(origin).origin())) {
            throw new IllegalStateException("Unexpected Agent Service origin.");
        }
    }
}
