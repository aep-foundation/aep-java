package foundation.aep.core;

import java.time.Clock;
import java.time.Duration;

public final class ClientAssertionVerification {
    private final String expectedAudience;
    private final String expectedIssuer;
    private final AssertionOperation expectedOperation;
    private final String expectedResource;
    private final Clock verificationClock;
    private final Duration allowedClockSkew;
    private final boolean insecureLoopbackAllowed;

    private ClientAssertionVerification(Builder builder) {
        expectedAudience = builder.configuredAudience;
        expectedIssuer = builder.configuredIssuer;
        expectedOperation = builder.configuredOperation;
        expectedResource = builder.configuredResource;
        verificationClock = builder.configuredClock;
        allowedClockSkew = builder.configuredClockSkew;
        insecureLoopbackAllowed = builder.configuredInsecureLoopback;
        if (expectedAudience == null || expectedIssuer == null || expectedOperation == null) {
            throw new IllegalArgumentException("Audience, issuer, and operation are required.");
        }
        if (allowedClockSkew.isNegative()) {
            throw new IllegalArgumentException("Clock skew must not be negative.");
        }
    }

    public static Builder builder(String audience, String issuer, AssertionOperation operation) {
        return new Builder(audience, issuer, operation);
    }

    public String audience() {
        return expectedAudience;
    }

    public String issuer() {
        return expectedIssuer;
    }

    public AssertionOperation operation() {
        return expectedOperation;
    }

    public String resource() {
        return expectedResource;
    }

    public Clock clock() {
        return verificationClock;
    }

    public Duration clockSkew() {
        return allowedClockSkew;
    }

    public boolean allowInsecureLoopback() {
        return insecureLoopbackAllowed;
    }

    public static final class Builder {
        private final String configuredAudience;
        private final String configuredIssuer;
        private final AssertionOperation configuredOperation;
        private String configuredResource;
        private Clock configuredClock = Clock.systemUTC();
        private Duration configuredClockSkew = Aep.RECOMMENDED_CLOCK_SKEW;
        private boolean configuredInsecureLoopback;

        private Builder(String audience, String issuer, AssertionOperation operation) {
            configuredAudience = audience;
            configuredIssuer = issuer;
            configuredOperation = operation;
        }

        public Builder resource(String value) {
            configuredResource = value;
            return this;
        }

        public Builder clock(Clock value) {
            configuredClock = java.util.Objects.requireNonNull(value, "clock");
            return this;
        }

        public Builder clockSkew(Duration value) {
            configuredClockSkew = java.util.Objects.requireNonNull(value, "clockSkew");
            return this;
        }

        public Builder allowInsecureLoopback(boolean value) {
            configuredInsecureLoopback = value;
            return this;
        }

        public ClientAssertionVerification build() {
            return new ClientAssertionVerification(this);
        }
    }
}
