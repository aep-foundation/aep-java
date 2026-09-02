package foundation.aep.agent;

import foundation.aep.core.ClientAssertionClaims;
import java.util.Objects;
import java.util.concurrent.CompletionStage;

public record AgentIdentity(String did, AssertionSigner signer) {
    public AgentIdentity {
        Objects.requireNonNull(did, "did");
        Objects.requireNonNull(signer, "signer");
    }

    @Override
    public String toString() {
        return "AgentIdentity[did=" + did + ", signer=<redacted>]";
    }

    @FunctionalInterface
    public interface AssertionSigner {
        CompletionStage<String> sign(ClientAssertionClaims claims);
    }
}
