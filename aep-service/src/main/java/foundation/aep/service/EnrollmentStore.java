package foundation.aep.service;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.function.Supplier;

public interface EnrollmentStore {
    CompletionStage<Optional<EnrollmentRecord>> find(String agentDid);

    CompletionStage<EnrollmentSelection> findOrCreate(
            String agentDid, Supplier<CompletionStage<EnrollmentRecord>> create);

    CompletionStage<EnrollmentRecord> save(EnrollmentRecord record);

    static EnrollmentStore inMemory() {
        return new InMemoryEnrollmentStore();
    }

    final class InMemoryEnrollmentStore implements EnrollmentStore {
        private final Map<String, EnrollmentRecord> records = new LinkedHashMap<>();
        private final Map<String, CompletableFuture<EnrollmentRecord>> pending = new LinkedHashMap<>();

        @Override
        public synchronized CompletionStage<Optional<EnrollmentRecord>> find(String agentDid) {
            return CompletableFuture.completedFuture(Optional.ofNullable(records.get(agentDid)));
        }

        @Override
        public CompletionStage<EnrollmentSelection> findOrCreate(
                String agentDid, Supplier<CompletionStage<EnrollmentRecord>> create) {
            CompletableFuture<EnrollmentRecord> operation;
            boolean created;
            synchronized (this) {
                EnrollmentRecord existing = records.get(agentDid);
                if (existing != null) {
                    return CompletableFuture.completedFuture(new EnrollmentSelection(existing, false));
                }
                operation = pending.get(agentDid);
                created = operation == null;
                if (created) {
                    operation = new CompletableFuture<>();
                    pending.put(agentDid, operation);
                }
            }
            if (!created) {
                return operation.thenApply(record -> new EnrollmentSelection(record, false));
            }
            CompletableFuture<EnrollmentRecord> destination = operation;
            CompletionStage<EnrollmentRecord> source;
            try {
                source = create.get();
            } catch (RuntimeException exception) {
                complete(agentDid, destination, null, exception);
                return destination.thenApply(record -> new EnrollmentSelection(record, true));
            }
            source.whenComplete((record, failure) -> complete(agentDid, destination, record, failure));
            return destination.thenApply(record -> new EnrollmentSelection(record, true));
        }

        @Override
        public CompletionStage<EnrollmentRecord> save(EnrollmentRecord record) {
            CompletableFuture<EnrollmentRecord> creation;
            synchronized (this) {
                creation = pending.get(record.agentDid());
                if (creation == null) {
                    records.put(record.agentDid(), record);
                    return CompletableFuture.completedFuture(record);
                }
            }
            return creation.handle((ignored, failure) -> record).thenCompose(this::save);
        }

        private synchronized void complete(
                String agentDid,
                CompletableFuture<EnrollmentRecord> destination,
                EnrollmentRecord record,
                Throwable failure) {
            pending.remove(agentDid);
            if (failure != null) {
                destination.completeExceptionally(failure);
                return;
            }
            if (!agentDid.equals(record.agentDid())) {
                destination.completeExceptionally(
                        new IllegalArgumentException("Enrollment record Agent DID mismatch."));
                return;
            }
            records.put(agentDid, record);
            destination.complete(record);
        }
    }
}
