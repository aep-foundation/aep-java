package foundation.aep.platform;

import java.util.concurrent.CompletionStage;

@FunctionalInterface
public interface PlatformServiceDidResolver {
    CompletionStage<Boolean> resolve(String serviceDid, PlatformRequestContext context);
}
