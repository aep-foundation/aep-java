package foundation.aep.agent;

import foundation.aep.core.ClientAssertionClaims;
import foundation.aep.core.PlatformAgentIdentity;
import java.util.Map;
import java.util.concurrent.CompletionStage;

@FunctionalInterface
public interface PlatformContextProvider {
    CompletionStage<Map<String, Object>> context(PlatformAgentIdentity identity, ClientAssertionClaims claims);
}
