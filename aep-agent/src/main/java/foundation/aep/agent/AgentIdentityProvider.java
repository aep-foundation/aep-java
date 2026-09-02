package foundation.aep.agent;

import java.net.URI;
import java.util.concurrent.CompletionStage;

@FunctionalInterface
public interface AgentIdentityProvider {
    CompletionStage<AgentIdentity> getOrCreate(URI serviceOrigin, String serviceDid);
}
