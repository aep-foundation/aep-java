package foundation.aep.platform;

import foundation.aep.core.PlatformSignRequest;
import foundation.aep.core.PlatformSignResponses;
import java.util.Optional;
import java.util.concurrent.CompletionStage;

@FunctionalInterface
public interface PlatformSignHandler {
    CompletionStage<Optional<PlatformResponse<PlatformSignResponses.Response>>> sign(
            PlatformIdentityRecord identity, PlatformSignRequest request, PlatformRequestContext context);
}
