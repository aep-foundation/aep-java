package foundation.aep.platform;

import foundation.aep.core.ManagedAgentStatus;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

public interface PlatformLifecyclePolicy {
    CompletionStage<Boolean> canSign(PlatformIdentityRecord identity, PlatformRequestContext context);

    CompletionStage<Boolean> canTransition(
            PlatformIdentityRecord identity, ManagedAgentStatus nextStatus, PlatformRequestContext context);

    CompletionStage<Boolean> canVerify(PlatformIdentityRecord identity, PlatformRequestContext context);

    static PlatformLifecyclePolicy permissiveTransitions() {
        return new PlatformLifecyclePolicy() {
            @Override
            public CompletionStage<Boolean> canSign(PlatformIdentityRecord identity, PlatformRequestContext context) {
                return CompletableFuture.completedFuture(identity.status() == ManagedAgentStatus.ACTIVE);
            }

            @Override
            public CompletionStage<Boolean> canTransition(
                    PlatformIdentityRecord identity, ManagedAgentStatus nextStatus, PlatformRequestContext context) {
                return CompletableFuture.completedFuture(true);
            }

            @Override
            public CompletionStage<Boolean> canVerify(PlatformIdentityRecord identity, PlatformRequestContext context) {
                return CompletableFuture.completedFuture(identity.status() == ManagedAgentStatus.ACTIVE);
            }
        };
    }
}
