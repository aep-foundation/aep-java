package foundation.aep.service;

import java.time.Instant;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

@FunctionalInterface
public interface ReplayStore {
    CompletionStage<Boolean> consume(ReplayRecord record, Instant now);

    static ReplayStore inMemory() {
        return new ReplayStore() {
            private final java.util.Map<String, ReplayRecord> records = new java.util.HashMap<>();

            @Override
            public synchronized CompletionStage<Boolean> consume(ReplayRecord record, Instant now) {
                records.values().removeIf(existing -> !existing.expiresAt().isAfter(now));
                if (record.subject().isBlank()
                        || record.jwtId().isBlank()
                        || !record.expiresAt().isAfter(now)) {
                    return CompletableFuture.failedFuture(new IllegalArgumentException("Invalid replay record."));
                }
                String key = record.subject() + '\0' + record.jwtId();
                if (records.containsKey(key)) {
                    return CompletableFuture.completedFuture(false);
                }
                records.put(key, record);
                return CompletableFuture.completedFuture(true);
            }
        };
    }
}
