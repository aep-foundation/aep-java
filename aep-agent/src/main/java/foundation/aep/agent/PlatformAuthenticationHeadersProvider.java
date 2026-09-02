package foundation.aep.agent;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletionStage;

@FunctionalInterface
public interface PlatformAuthenticationHeadersProvider {
    CompletionStage<Map<String, List<String>>> headers();
}
