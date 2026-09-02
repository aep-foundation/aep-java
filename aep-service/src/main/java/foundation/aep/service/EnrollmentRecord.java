package foundation.aep.service;

import foundation.aep.core.AgentStatus;
import foundation.aep.core.ClaimValues;
import java.time.Instant;
import java.util.List;
import java.util.Objects;

public final class EnrollmentRecord {
    private final String recordAgentDid;
    private final String recordEnrollmentId;
    private final AgentStatus recordStatus;
    private final ClaimValues recordClaims;
    private final Instant recordCreatedAt;
    private final Instant recordUpdatedAt;
    private final Instant recordSince;
    private final boolean recordOwnerActionRequired;
    private final List<String> recordVerificationPending;
    private final List<String> recordRequirementsPending;

    private EnrollmentRecord(Builder builder) {
        recordAgentDid = requireText(builder.configuredAgentDid, "agentDid");
        recordEnrollmentId = requireText(builder.configuredEnrollmentId, "enrollmentId");
        recordStatus = Objects.requireNonNull(builder.configuredStatus, "status");
        recordClaims = copyClaims(builder.configuredClaims);
        recordCreatedAt = Objects.requireNonNull(builder.configuredCreatedAt, "createdAt");
        recordUpdatedAt = Objects.requireNonNull(builder.configuredUpdatedAt, "updatedAt");
        recordSince = Objects.requireNonNull(builder.configuredSince, "since");
        recordOwnerActionRequired = builder.configuredOwnerActionRequired;
        recordVerificationPending = List.copyOf(builder.configuredVerificationPending);
        recordRequirementsPending = List.copyOf(builder.configuredRequirementsPending);
    }

    public static Builder builder(String agentDid, String enrollmentId, AgentStatus status, Instant createdAt) {
        return new Builder(agentDid, enrollmentId, status, createdAt);
    }

    public String agentDid() {
        return recordAgentDid;
    }

    public String enrollmentId() {
        return recordEnrollmentId;
    }

    public AgentStatus status() {
        return recordStatus;
    }

    public ClaimValues claims() {
        return copyClaims(recordClaims);
    }

    public Instant createdAt() {
        return recordCreatedAt;
    }

    public Instant updatedAt() {
        return recordUpdatedAt;
    }

    public Instant since() {
        return recordSince;
    }

    public boolean ownerActionRequired() {
        return recordOwnerActionRequired;
    }

    public List<String> verificationPending() {
        return recordVerificationPending;
    }

    public List<String> requirementsPending() {
        return recordRequirementsPending;
    }

    public static final class Builder {
        private final String configuredAgentDid;
        private final String configuredEnrollmentId;
        private final Instant configuredCreatedAt;
        private AgentStatus configuredStatus;
        private ClaimValues configuredClaims;
        private Instant configuredUpdatedAt;
        private Instant configuredSince;
        private boolean configuredOwnerActionRequired;
        private List<String> configuredVerificationPending = List.of();
        private List<String> configuredRequirementsPending = List.of();

        private Builder(String agentDid, String enrollmentId, AgentStatus status, Instant createdAt) {
            configuredAgentDid = agentDid;
            configuredEnrollmentId = enrollmentId;
            configuredStatus = status;
            configuredCreatedAt = createdAt;
            configuredUpdatedAt = createdAt;
            configuredSince = createdAt;
        }

        public Builder status(AgentStatus value) {
            configuredStatus = value;
            return this;
        }

        public Builder claims(ClaimValues value) {
            configuredClaims = copyClaims(value);
            return this;
        }

        public Builder updatedAt(Instant value) {
            configuredUpdatedAt = value;
            return this;
        }

        public Builder since(Instant value) {
            configuredSince = value;
            return this;
        }

        public Builder ownerActionRequired(boolean value) {
            configuredOwnerActionRequired = value;
            return this;
        }

        public Builder verificationPending(List<String> value) {
            configuredVerificationPending = List.copyOf(value);
            return this;
        }

        public Builder requirementsPending(List<String> value) {
            configuredRequirementsPending = List.copyOf(value);
            return this;
        }

        public EnrollmentRecord build() {
            return new EnrollmentRecord(this);
        }
    }

    private static String requireText(String value, String name) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException(name + " must not be blank");
        return value;
    }

    private static ClaimValues copyClaims(ClaimValues value) {
        if (value == null) return null;
        ClaimValues.Builder builder = ClaimValues.builder()
                .contactAddressPrimary(value.contactAddressPrimary())
                .contactEmail(value.contactEmail())
                .contactMobile(value.contactMobile())
                .personBirthdate(value.personBirthdate())
                .personFirstName(value.personFirstName())
                .personLastName(value.personLastName())
                .personUsername(value.personUsername());
        value.additional().forEach(builder::additional);
        return builder.build();
    }
}
