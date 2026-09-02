package foundation.aep.agent;

import java.util.Map;
import java.util.concurrent.CompletionStage;

@FunctionalInterface
public interface PlatformPendingSignResolver {
    CompletionStage<Map<String, Object>> resolve(PlatformPendingSign pending);
}
