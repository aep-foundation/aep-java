package foundation.aep.platform;

import java.util.concurrent.CompletionStage;

@FunctionalInterface
public interface PlatformAuthorizer {
    CompletionStage<Boolean> authorize(PlatformAuthorizationRequest request, PlatformRequestContext context);
}
