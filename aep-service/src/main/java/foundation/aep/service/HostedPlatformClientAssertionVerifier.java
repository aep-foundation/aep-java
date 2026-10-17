package foundation.aep.service;

import foundation.aep.core.Aep;
import foundation.aep.core.AepHttpTransport;
import foundation.aep.core.AepJson;
import foundation.aep.core.ClientAssertionClaims;
import foundation.aep.core.ClientAssertions;
import foundation.aep.core.PlatformVerificationRequest;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.TimeUnit;

/** Verifies assertions through an explicitly trusted Platform, not an assertion-supplied URL. */
public final class HostedPlatformClientAssertionVerifier implements ClientAssertionVerifier {
    private final URI endpoint;
    private final AepHttpTransport transport;
    private final String authorization;
    private final Duration timeout;

    private HostedPlatformClientAssertionVerifier(Builder builder) {
        endpoint = Objects.requireNonNull(builder.endpoint, "endpoint");
        if (!"https".equalsIgnoreCase(endpoint.getScheme())
                || endpoint.getHost() == null
                || endpoint.getRawUserInfo() != null
                || endpoint.getRawFragment() != null) {
            throw new IllegalArgumentException(
                    "Hosted verification requires an HTTPS endpoint without credentials or a fragment.");
        }
        transport = Objects.requireNonNull(builder.transport, "transport");
        authorization = builder.authorizationValue;
        timeout = Objects.requireNonNull(builder.timeoutValue, "timeout");
        if (timeout.isNegative() || timeout.isZero() || timeout.toMillis() < 1) {
            throw new IllegalArgumentException("Hosted verification timeout must be at least one millisecond.");
        }
    }

    public static Builder builder(URI endpoint, AepHttpTransport transport) {
        return new Builder(endpoint, transport);
    }

    @Override
    public CompletionStage<ClientAssertionClaims> verify(String assertion, AssertionVerificationContext context) {
        ClientAssertionClaims claims = ClientAssertions.decodeUnverified(assertion);
        byte[] body = AepJson.write(new PlatformVerificationRequest(
                        assertion, context.operation(), context.resource(), context.serviceDid()))
                .getBytes(StandardCharsets.UTF_8);
        Map<String, List<String>> headers = new LinkedHashMap<>();
        headers.put("Accept", List.of(Aep.MEDIA_TYPE));
        headers.put("Content-Type", List.of(Aep.MEDIA_TYPE));
        if (authorization != null) headers.put("Authorization", List.of(authorization));
        // Command retries can carry fresh assertions; only an identical verification request reuses this key.
        headers.put("Idempotency-Key", List.of(digest(body)));
        return transport
                .execute(new AepHttpTransport.Request("POST", endpoint, headers, body, timeout))
                .toCompletableFuture()
                .copy()
                .orTimeout(timeout.toMillis(), TimeUnit.MILLISECONDS)
                .thenApply(response -> {
                    if (response.status() < 200 || response.status() >= 300) {
                        throw new IllegalArgumentException(
                                "Hosted verification failed with HTTP " + response.status() + ".");
                    }
                    var verification = AepJson.parsePlatformVerificationResponse(
                            new String(response.body(), StandardCharsets.UTF_8));
                    if (!verification.verified()
                            || !Objects.equals(verification.agentDid(), claims.subject())
                            || verification.operation() != context.operation()
                            || !Objects.equals(verification.serviceDid(), context.serviceDid())) {
                        throw new IllegalArgumentException(
                                "Hosted verification did not recognize the client assertion.");
                    }
                    return claims;
                });
    }

    private static String digest(byte[] body) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(body));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable.", exception);
        }
    }

    public static final class Builder {
        private final URI endpoint;
        private final AepHttpTransport transport;
        private String authorizationValue;
        private Duration timeoutValue = Duration.ofSeconds(30);

        private Builder(URI endpoint, AepHttpTransport transport) {
            this.endpoint = endpoint;
            this.transport = transport;
        }

        public Builder authorization(String value) {
            authorizationValue = value;
            return this;
        }

        public Builder timeout(Duration value) {
            timeoutValue = value;
            return this;
        }

        /** The transport must honor request timeouts and return redirects without following them. */
        public HostedPlatformClientAssertionVerifier build() {
            return new HostedPlatformClientAssertionVerifier(this);
        }
    }
}
