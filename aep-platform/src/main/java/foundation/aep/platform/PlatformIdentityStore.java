package foundation.aep.platform;

import foundation.aep.core.ManagedAgentStatus;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.function.Supplier;

public interface PlatformIdentityStore {
    CompletionStage<PlatformIdentitySelection> findOrCreate(
            String principal, String serviceDid, Supplier<CompletionStage<PlatformIdentityRecord>> create);

    CompletionStage<Optional<PlatformIdentityRecord>> findByAgentDid(String agentDid);

    CompletionStage<Optional<PlatformIdentityRecord>> findByAgentDidId(String agentDidId);

    CompletionStage<Optional<PlatformIdentityRecord>> get(String agentIdentityId);

    CompletionStage<PlatformIdentityListResult> list(String principal, PlatformIdentityListQuery query);

    CompletionStage<Optional<PlatformIdentityRecord>> update(
            String agentIdentityId, ManagedAgentStatus status, Instant updatedAt);

    static PlatformIdentityStore inMemory() {
        return new InMemoryPlatformIdentityStore();
    }

    final class InMemoryPlatformIdentityStore implements PlatformIdentityStore {
        private final Map<String, PlatformIdentityRecord> records = new LinkedHashMap<>();
        private final Map<String, String> byAgentDid = new LinkedHashMap<>();
        private final Map<String, String> byAgentDidId = new LinkedHashMap<>();
        private final Map<String, String> byScope = new LinkedHashMap<>();
        private final Map<String, CompletableFuture<PlatformIdentityRecord>> pending = new LinkedHashMap<>();

        @Override
        public CompletionStage<PlatformIdentitySelection> findOrCreate(
                String principal, String serviceDid, Supplier<CompletionStage<PlatformIdentityRecord>> create) {
            requireText(principal, "principal");
            requireText(serviceDid, "serviceDid");
            java.util.Objects.requireNonNull(create, "create");
            String scope = scope(principal, serviceDid);
            CompletableFuture<PlatformIdentityRecord> operation;
            boolean created;
            synchronized (this) {
                String identityId = byScope.get(scope);
                if (identityId != null) {
                    return CompletableFuture.completedFuture(
                            new PlatformIdentitySelection(records.get(identityId), false));
                }
                operation = pending.get(scope);
                created = operation == null;
                if (created) {
                    operation = new CompletableFuture<>();
                    pending.put(scope, operation);
                }
            }
            if (!created) {
                return operation.thenApply(identity -> new PlatformIdentitySelection(identity, false));
            }
            CompletableFuture<PlatformIdentityRecord> destination = operation;
            CompletionStage<PlatformIdentityRecord> source;
            try {
                source = create.get();
            } catch (RuntimeException exception) {
                complete(scope, principal, serviceDid, destination, null, exception);
                return destination.thenApply(identity -> new PlatformIdentitySelection(identity, true));
            }
            source.whenComplete(
                    (identity, failure) -> complete(scope, principal, serviceDid, destination, identity, failure));
            return destination.thenApply(identity -> new PlatformIdentitySelection(identity, true));
        }

        @Override
        public synchronized CompletionStage<Optional<PlatformIdentityRecord>> findByAgentDid(String agentDid) {
            return find(byAgentDid.get(agentDid));
        }

        @Override
        public synchronized CompletionStage<Optional<PlatformIdentityRecord>> findByAgentDidId(String agentDidId) {
            return find(byAgentDidId.get(agentDidId));
        }

        @Override
        public synchronized CompletionStage<Optional<PlatformIdentityRecord>> get(String agentIdentityId) {
            return CompletableFuture.completedFuture(Optional.ofNullable(records.get(agentIdentityId)));
        }

        @Override
        public synchronized CompletionStage<PlatformIdentityListResult> list(
                String principal, PlatformIdentityListQuery query) {
            requireText(principal, "principal");
            java.util.Objects.requireNonNull(query, "query");
            if (query.limit() < 1 || query.limit() > 100 || query.offset() < 0) {
                throw new IllegalArgumentException("query limit or offset is invalid");
            }
            List<PlatformIdentityRecord> selected = new ArrayList<>();
            for (PlatformIdentityRecord identity : records.values()) {
                if (!identity.principal().equals(principal)) continue;
                if (query.serviceDid() != null && !query.serviceDid().equals(identity.serviceDid())) continue;
                if (query.status() != null && query.status() != identity.status()) continue;
                selected.add(identity);
            }
            Comparator<PlatformIdentityRecord> order = Comparator.comparing(PlatformIdentityRecord::createdAt)
                    .thenComparing(PlatformIdentityRecord::agentIdentityId);
            selected.sort(query.descending() ? order.reversed() : order);
            int total = selected.size();
            int from = Math.min(query.offset(), total);
            int to = (int) Math.min((long) from + query.limit(), total);
            return CompletableFuture.completedFuture(
                    new PlatformIdentityListResult(List.copyOf(selected.subList(from, to)), total));
        }

        @Override
        public synchronized CompletionStage<Optional<PlatformIdentityRecord>> update(
                String agentIdentityId, ManagedAgentStatus status, Instant updatedAt) {
            PlatformIdentityRecord identity = records.get(agentIdentityId);
            if (identity == null) return CompletableFuture.completedFuture(Optional.empty());
            PlatformIdentityRecord updated = identity.toBuilder()
                    .status(java.util.Objects.requireNonNull(status, "status"))
                    .updatedAt(java.util.Objects.requireNonNull(updatedAt, "updatedAt"))
                    .build();
            records.put(agentIdentityId, updated);
            return CompletableFuture.completedFuture(Optional.of(updated));
        }

        private synchronized CompletionStage<Optional<PlatformIdentityRecord>> find(String identityId) {
            return CompletableFuture.completedFuture(
                    identityId == null ? Optional.empty() : Optional.of(records.get(identityId)));
        }

        private synchronized void complete(
                String scope,
                String principal,
                String serviceDid,
                CompletableFuture<PlatformIdentityRecord> destination,
                PlatformIdentityRecord identity,
                Throwable failure) {
            pending.remove(scope);
            if (failure != null) {
                destination.completeExceptionally(failure);
                return;
            }
            if (identity == null
                    || !principal.equals(identity.principal())
                    || !serviceDid.equals(identity.serviceDid())) {
                destination.completeExceptionally(
                        new IllegalArgumentException("Platform identity does not match its requested scope."));
                return;
            }
            if (records.containsKey(identity.agentIdentityId())
                    || byAgentDid.containsKey(identity.agentDid())
                    || byAgentDidId.containsKey(identity.agentDidId())) {
                destination.completeExceptionally(
                        new IllegalArgumentException("Platform identity material must be unique."));
                return;
            }
            records.put(identity.agentIdentityId(), identity);
            byAgentDid.put(identity.agentDid(), identity.agentIdentityId());
            byAgentDidId.put(identity.agentDidId(), identity.agentIdentityId());
            byScope.put(scope, identity.agentIdentityId());
            destination.complete(identity);
        }

        private static String scope(String principal, String serviceDid) {
            return principal + '\0' + serviceDid;
        }

        private static void requireText(String value, String name) {
            if (value == null || value.isBlank()) throw new IllegalArgumentException(name + " must not be blank");
        }
    }
}
