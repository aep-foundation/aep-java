package foundation.aep.example;

import foundation.aep.agent.AepAgent;
import foundation.aep.agent.AgentIdentity;
import foundation.aep.agent.PlatformIdentityProvider;
import foundation.aep.core.AepJson;
import foundation.aep.core.RevokeResponse;
import foundation.aep.httpserver.AepHttpServer;
import foundation.aep.servlet.AepServlet;
import foundation.aep.spring.webmvc.AepSpringWebMvc;
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
        requirePublicType(AepHttpServer.class);
        requirePublicType(AepServlet.class);
        requirePublicType(AepSpringWebMvc.class);
        requirePublicType(PlatformIdentityProvider.class);

        PlatformIdentityProvider hostedIdentities = PlatformIdentityProvider
                .builder(URI.create("https://platform.example"))
                .transport(request -> CompletableFuture.failedFuture(new UnsupportedOperationException()))
                .build();
        requirePublicType(hostedIdentities.getClass());

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

    private static void requirePublicType(Class<?> type) {
        if (!type.getName().startsWith("foundation.aep.")) {
            throw new IllegalStateException("Unexpected AEP public type.");
        }
    }
}
