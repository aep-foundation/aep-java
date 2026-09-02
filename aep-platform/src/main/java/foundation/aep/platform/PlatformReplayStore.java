package foundation.aep.platform;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

@FunctionalInterface
public interface PlatformReplayStore {
    CompletionStage<Boolean> consume(String key, Instant expiresAt, Instant now, PlatformRequestContext context);

    static PlatformReplayStore inMemory() {
        return new PlatformReplayStore() {
            private final Map<String, Instant> entries = new HashMap<>();

            @Override
            public synchronized CompletionStage<Boolean> consume(
                    String key, Instant expiresAt, Instant now, PlatformRequestContext context) {
                if (key == null || key.isBlank() || expiresAt == null || now == null) {
                    return CompletableFuture.failedFuture(new IllegalArgumentException("Invalid replay input."));
                }
                entries.values().removeIf(expiry -> !expiry.isAfter(now));
                if (!expiresAt.isAfter(now) || entries.containsKey(key)) {
                    return CompletableFuture.completedFuture(false);
                }
                entries.put(key, expiresAt);
                return CompletableFuture.completedFuture(true);
            }
        };
    }
}
