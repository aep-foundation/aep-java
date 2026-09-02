package foundation.aep.platform;

import foundation.aep.core.ManagedAgentStatus;
import java.time.Instant;
import java.util.List;

public final class PlatformIdentityRecord {
    private final String storedAgentDid;
    private final String storedAgentDidId;
    private final String storedAgentIdentityId;
    private final Instant storedCreatedAt;
    private final String storedDidDocumentUrl;
    private final String storedKeyId;
    private final String storedPrincipal;
    private final String storedServiceDid;
    private final List<String> storedSigningAlgorithms;
    private final ManagedAgentStatus storedStatus;
    private final Instant storedUpdatedAt;

    private PlatformIdentityRecord(Builder builder) {
        storedAgentDid = requireText(builder.configuredAgentDid, "agentDid");
        storedAgentDidId = requireText(builder.configuredAgentDidId, "agentDidId");
        storedAgentIdentityId = requireText(builder.configuredAgentIdentityId, "agentIdentityId");
        storedCreatedAt = java.util.Objects.requireNonNull(builder.configuredCreatedAt, "createdAt");
        storedDidDocumentUrl = requireText(builder.configuredDidDocumentUrl, "didDocumentUrl");
        storedKeyId = requireText(builder.configuredKeyId, "keyId");
        storedPrincipal = requireText(builder.configuredPrincipal, "principal");
        storedServiceDid = requireText(builder.configuredServiceDid, "serviceDid");
        storedSigningAlgorithms = List.copyOf(builder.configuredSigningAlgorithms);
        if (storedSigningAlgorithms.isEmpty())
            throw new IllegalArgumentException("signingAlgorithms must not be empty");
        storedStatus = java.util.Objects.requireNonNull(builder.configuredStatus, "status");
        storedUpdatedAt = java.util.Objects.requireNonNull(builder.configuredUpdatedAt, "updatedAt");
    }

    public static Builder builder() {
        return new Builder();
    }

    public Builder toBuilder() {
        return new Builder()
                .agentDid(storedAgentDid)
                .agentDidId(storedAgentDidId)
                .agentIdentityId(storedAgentIdentityId)
                .createdAt(storedCreatedAt)
                .didDocumentUrl(storedDidDocumentUrl)
                .keyId(storedKeyId)
                .principal(storedPrincipal)
                .serviceDid(storedServiceDid)
                .signingAlgorithms(storedSigningAlgorithms)
                .status(storedStatus)
                .updatedAt(storedUpdatedAt);
    }

    public String agentDid() {
        return storedAgentDid;
    }

    public String agentDidId() {
        return storedAgentDidId;
    }

    public String agentIdentityId() {
        return storedAgentIdentityId;
    }

    public Instant createdAt() {
        return storedCreatedAt;
    }

    public String didDocumentUrl() {
        return storedDidDocumentUrl;
    }

    public String keyId() {
        return storedKeyId;
    }

    public String principal() {
        return storedPrincipal;
    }

    public String serviceDid() {
        return storedServiceDid;
    }

    public List<String> signingAlgorithms() {
        return List.copyOf(storedSigningAlgorithms);
    }

    public ManagedAgentStatus status() {
        return storedStatus;
    }

    public Instant updatedAt() {
        return storedUpdatedAt;
    }

    @Override
    public String toString() {
        return "PlatformIdentityRecord[agentDid=" + storedAgentDid + ", agentDidId=<redacted>, agentIdentityId="
                + storedAgentIdentityId + ", createdAt=" + storedCreatedAt + ", didDocumentUrl="
                + storedDidDocumentUrl + ", keyId=" + storedKeyId + ", principal=<redacted>, serviceDid="
                + storedServiceDid + ", signingAlgorithms=" + storedSigningAlgorithms + ", status=" + storedStatus
                + ", updatedAt=" + storedUpdatedAt + "]";
    }

    public static final class Builder {
        private String configuredAgentDid;
        private String configuredAgentDidId;
        private String configuredAgentIdentityId;
        private Instant configuredCreatedAt;
        private String configuredDidDocumentUrl;
        private String configuredKeyId;
        private String configuredPrincipal;
        private String configuredServiceDid;
        private List<String> configuredSigningAlgorithms = List.of();
        private ManagedAgentStatus configuredStatus;
        private Instant configuredUpdatedAt;

        public Builder agentDid(String value) {
            configuredAgentDid = value;
            return this;
        }

        public Builder agentDidId(String value) {
            configuredAgentDidId = value;
            return this;
        }

        public Builder agentIdentityId(String value) {
            configuredAgentIdentityId = value;
            return this;
        }

        public Builder createdAt(Instant value) {
            configuredCreatedAt = value;
            return this;
        }

        public Builder didDocumentUrl(String value) {
            configuredDidDocumentUrl = value;
            return this;
        }

        public Builder keyId(String value) {
            configuredKeyId = value;
            return this;
        }

        public Builder principal(String value) {
            configuredPrincipal = value;
            return this;
        }

        public Builder serviceDid(String value) {
            configuredServiceDid = value;
            return this;
        }

        public Builder signingAlgorithms(List<String> value) {
            configuredSigningAlgorithms = List.copyOf(value);
            return this;
        }

        public Builder status(ManagedAgentStatus value) {
            configuredStatus = value;
            return this;
        }

        public Builder updatedAt(Instant value) {
            configuredUpdatedAt = value;
            return this;
        }

        public PlatformIdentityRecord build() {
            return new PlatformIdentityRecord(this);
        }
    }

    private static String requireText(String value, String name) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException(name + " must not be blank");
        return value;
    }
}
