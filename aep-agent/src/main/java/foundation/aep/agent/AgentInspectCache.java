package foundation.aep.agent;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ConcurrentHashMap;

public interface AgentInspectCache {
    CompletionStage<Optional<Entry>> get(URI origin);

    CompletionStage<Void> put(URI origin, Entry entry);

    CompletionStage<Void> delete(URI origin);

    record Entry(
            URI documentUri,
            String json,
            String etag,
            String lastModified,
            Instant expiresAt,
            Map<String, List<String>> cacheHeaders) {
        public Entry(URI documentUri, String json, String etag, String lastModified, Instant expiresAt) {
            this(documentUri, json, etag, lastModified, expiresAt, Map.of());
        }

        public Entry {
            Objects.requireNonNull(documentUri, "documentUri");
            Objects.requireNonNull(json, "json");
            Objects.requireNonNull(expiresAt, "expiresAt");
            cacheHeaders = Map.copyOf(cacheHeaders.entrySet().stream()
                    .collect(java.util.stream.Collectors.toUnmodifiableMap(
                            Map.Entry::getKey, entry -> List.copyOf(entry.getValue()))));
        }
    }

    static AgentInspectCache none() {
        return new AgentInspectCache() {
            @Override
            public CompletionStage<Optional<Entry>> get(URI origin) {
                return CompletableFuture.completedFuture(Optional.empty());
            }

            @Override
            public CompletionStage<Void> put(URI origin, Entry entry) {
                return CompletableFuture.completedFuture(null);
            }

            @Override
            public CompletionStage<Void> delete(URI origin) {
                return CompletableFuture.completedFuture(null);
            }
        };
    }

    static AgentInspectCache inMemory() {
        return new AgentInspectCache() {
            private final Map<URI, Entry> entries = new ConcurrentHashMap<>();

            @Override
            public CompletionStage<Optional<Entry>> get(URI origin) {
                return CompletableFuture.completedFuture(Optional.ofNullable(entries.get(origin)));
            }

            @Override
            public CompletionStage<Void> put(URI origin, Entry entry) {
                entries.put(origin, entry);
                return CompletableFuture.completedFuture(null);
            }

            @Override
            public CompletionStage<Void> delete(URI origin) {
                entries.remove(origin);
                return CompletableFuture.completedFuture(null);
            }
        };
    }
}
