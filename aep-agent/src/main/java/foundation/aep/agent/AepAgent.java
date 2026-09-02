package foundation.aep.agent;

import foundation.aep.core.AepHttpTransport;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Supplier;

public final class AepAgent {
    static final int DEFAULT_MAXIMUM_RESPONSE_BYTES = 1_048_576;
    static final int DEFAULT_MAXIMUM_REDIRECTS = 5;
    static final Duration DEFAULT_REQUEST_TIMEOUT = Duration.ofSeconds(30);
    static final Duration DEFAULT_ASSERTION_LIFETIME = Duration.ofMinutes(5);
    static final Duration DEFAULT_INSPECT_FRESHNESS = Duration.ofMinutes(5);

    final AepHttpTransport inspectTransport;
    final AepHttpTransport commandTransport;
    final AgentIdentityProvider identityProvider;
    final AgentCredentialStore credentialStore;
    final AgentInspectCache inspectCache;
    final AgentIdempotencyKeyProvider idempotencyKeyProvider;
    final List<AgentCredentialHandler> credentialHandlers;
    final Clock clock;
    final Supplier<String> jwtIdSupplier;
    final Duration requestTimeout;
    final Duration assertionLifetime;
    final Duration defaultInspectFreshness;
    final int maximumResponseBytes;
    final int maximumRedirects;
    final boolean allowInsecureLoopback;

    private AepAgent(Builder builder) {
        inspectTransport = builder.configuredInspectTransport;
        commandTransport = builder.configuredCommandTransport;
        identityProvider = builder.configuredIdentityProvider;
        credentialStore = builder.configuredCredentialStore;
        inspectCache = builder.configuredInspectCache;
        idempotencyKeyProvider = builder.configuredIdempotencyKeyProvider;
        credentialHandlers = List.copyOf(builder.configuredCredentialHandlers);
        clock = builder.configuredClock;
        jwtIdSupplier = builder.configuredJwtIdSupplier;
        requestTimeout = builder.configuredRequestTimeout;
        assertionLifetime = builder.configuredAssertionLifetime;
        defaultInspectFreshness = builder.configuredDefaultInspectFreshness;
        maximumResponseBytes = builder.configuredMaximumResponseBytes;
        maximumRedirects = builder.configuredMaximumRedirects;
        allowInsecureLoopback = builder.configuredAllowInsecureLoopback;
    }

    public static Builder builder() {
        return new Builder();
    }

    public AepServiceSession service(URI origin) {
        return new AepServiceSession(this, AgentHttp.origin(origin, allowInsecureLoopback));
    }

    public static final class Builder {
        private AepHttpTransport configuredInspectTransport;
        private AepHttpTransport configuredCommandTransport;
        private AgentIdentityProvider configuredIdentityProvider;
        private AgentCredentialStore configuredCredentialStore = AgentCredentialStore.inMemory();
        private AgentInspectCache configuredInspectCache = AgentInspectCache.inMemory();
        private AgentIdempotencyKeyProvider configuredIdempotencyKeyProvider =
                (serviceDid, command, discriminator) -> UUID.randomUUID().toString();
        private final List<AgentCredentialHandler> configuredCredentialHandlers = new ArrayList<>();
        private Clock configuredClock = Clock.systemUTC();
        private Supplier<String> configuredJwtIdSupplier =
                () -> UUID.randomUUID().toString();
        private Duration configuredRequestTimeout = DEFAULT_REQUEST_TIMEOUT;
        private Duration configuredAssertionLifetime = DEFAULT_ASSERTION_LIFETIME;
        private Duration configuredDefaultInspectFreshness = DEFAULT_INSPECT_FRESHNESS;
        private int configuredMaximumResponseBytes = DEFAULT_MAXIMUM_RESPONSE_BYTES;
        private int configuredMaximumRedirects = DEFAULT_MAXIMUM_REDIRECTS;
        private boolean configuredAllowInsecureLoopback;

        private Builder() {}

        public Builder inspectTransport(AepHttpTransport value) {
            configuredInspectTransport = Objects.requireNonNull(value, "inspectTransport");
            return this;
        }

        public Builder commandTransport(AepHttpTransport value) {
            configuredCommandTransport = Objects.requireNonNull(value, "commandTransport");
            return this;
        }

        public Builder identityProvider(AgentIdentityProvider value) {
            configuredIdentityProvider = Objects.requireNonNull(value, "identityProvider");
            return this;
        }

        public Builder credentialStore(AgentCredentialStore value) {
            configuredCredentialStore = Objects.requireNonNull(value, "credentialStore");
            return this;
        }

        public Builder inspectCache(AgentInspectCache value) {
            configuredInspectCache = Objects.requireNonNull(value, "inspectCache");
            return this;
        }

        public Builder idempotencyKeyProvider(AgentIdempotencyKeyProvider value) {
            configuredIdempotencyKeyProvider = Objects.requireNonNull(value, "idempotencyKeyProvider");
            return this;
        }

        public Builder credentialHandler(AgentCredentialHandler value) {
            configuredCredentialHandlers.add(Objects.requireNonNull(value, "credentialHandler"));
            return this;
        }

        public Builder clock(Clock value) {
            configuredClock = Objects.requireNonNull(value, "clock");
            return this;
        }

        public Builder jwtIdSupplier(Supplier<String> value) {
            configuredJwtIdSupplier = Objects.requireNonNull(value, "jwtIdSupplier");
            return this;
        }

        public Builder requestTimeout(Duration value) {
            configuredRequestTimeout = positive(value, "requestTimeout");
            return this;
        }

        public Builder assertionLifetime(Duration value) {
            configuredAssertionLifetime = positive(value, "assertionLifetime");
            if (configuredAssertionLifetime.compareTo(DEFAULT_ASSERTION_LIFETIME) > 0) {
                throw new IllegalArgumentException("assertionLifetime must not exceed five minutes");
            }
            return this;
        }

        public Builder defaultInspectFreshness(Duration value) {
            configuredDefaultInspectFreshness = positive(value, "defaultInspectFreshness");
            return this;
        }

        public Builder maximumResponseBytes(int value) {
            if (value <= 0) {
                throw new IllegalArgumentException("maximumResponseBytes must be positive");
            }
            configuredMaximumResponseBytes = value;
            return this;
        }

        public Builder maximumRedirects(int value) {
            if (value < 0) {
                throw new IllegalArgumentException("maximumRedirects must not be negative");
            }
            configuredMaximumRedirects = value;
            return this;
        }

        public Builder allowInsecureLoopback(boolean value) {
            configuredAllowInsecureLoopback = value;
            return this;
        }

        public AepAgent build() {
            Objects.requireNonNull(configuredInspectTransport, "inspectTransport");
            Objects.requireNonNull(configuredCommandTransport, "commandTransport");
            Objects.requireNonNull(configuredIdentityProvider, "identityProvider");
            requireUniqueHandlers();
            return new AepAgent(this);
        }

        private void requireUniqueHandlers() {
            configuredCredentialHandlers.forEach(handler -> {
                requireNonBlank(handler.authenticationMethod(), "authenticationMethod");
                requireNonBlank(handler.grantType(), "grantType");
            });
            long methods = configuredCredentialHandlers.stream()
                    .map(AgentCredentialHandler::authenticationMethod)
                    .distinct()
                    .count();
            long grants = configuredCredentialHandlers.stream()
                    .map(AgentCredentialHandler::grantType)
                    .distinct()
                    .count();
            if (methods != configuredCredentialHandlers.size() || grants != configuredCredentialHandlers.size()) {
                throw new IllegalArgumentException("Credential handlers must have unique methods and Grant Types");
            }
        }

        private static Duration positive(Duration value, String name) {
            Objects.requireNonNull(value, name);
            if (value.isZero() || value.isNegative()) {
                throw new IllegalArgumentException(name + " must be positive");
            }
            return value;
        }

        private static void requireNonBlank(String value, String name) {
            if (value == null || value.isBlank()) {
                throw new IllegalArgumentException(name + " must not be blank");
            }
        }
    }
}
