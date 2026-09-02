package foundation.aep.agent;

import foundation.aep.core.AepCommand;

@FunctionalInterface
public interface AgentIdempotencyKeyProvider {
    String keyFor(String serviceDid, AepCommand command, String discriminator);
}
