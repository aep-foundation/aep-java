package foundation.aep.service;

import foundation.aep.core.Aep;
import foundation.aep.core.AepHttp;
import foundation.aep.core.AepJson;
import foundation.aep.core.AuthorizationCarrier;
import foundation.aep.core.AuthorizationScheme;
import foundation.aep.core.GrantResponses;
import foundation.aep.core.ProtectedResourceAuthorization;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

final class InMemoryServiceCredentialStore implements ServiceCredentialStore {
    private static final int SINGLE_PRESENTATION = 1;
    private static final String AUTHORIZATION = "Authorization";
    private final Map<String, StoredRecord> records = new LinkedHashMap<>();

    @Override
    public synchronized CompletionStage<Optional<ServiceCredentialMatch>> authenticate(
            String grantType, CredentialAuthenticationInput input) {
        List<Presentation> presentations = presentations(grantType, input.headers());
        if (Aep.GRANT_TYPE_API_KEY.equals(grantType)) {
            // Header names are case-insensitive on the wire (APK-CFG-003), so two records spelling
            // the same header differently name one field. Deduplicating on the raw spelling harvested
            // that one field twice and tipped every API key into the ambiguity branch below.
            apiKeyHeaders().forEach(header -> presentations.addAll(apiKeyPresentations(input.headers(), header)));
        }
        if (presentations.size() != SINGLE_PRESENTATION) {
            return completed(Optional.empty());
        }
        Presentation presentation = presentations.get(0);
        byte[] verifier = digest(presentation.value());
        for (StoredRecord record : records.values()) {
            if (grantType.equals(record.grantType())
                    && record.header().equalsIgnoreCase(presentation.header())
                    && record.revokedAt() == null
                    && record.expiresAt().isAfter(input.now())
                    && MessageDigest.isEqual(record.verifier(), verifier)) {
                return completed(Optional.of(new ServiceCredentialMatch(
                        record.agentDid(),
                        record.credentialId(),
                        record.expiresAt(),
                        record.grantType(),
                        record.scopes())));
            }
        }
        return completed(Optional.empty());
    }

    @Override
    public synchronized CompletionStage<Boolean> hasPresentation(
            String grantType, CredentialAuthenticationInput input) {
        if (!Aep.GRANT_TYPE_API_KEY.equals(grantType)) {
            return completed(!presentations(grantType, input.headers()).isEmpty());
        }
        Map<String, List<String>> headers = input.headers();
        boolean present = apiKeyHeaders().stream()
                .anyMatch(header -> !headerValues(headers, header).isEmpty());
        return completed(present);
    }

    @Override
    public synchronized CompletionStage<Void> revoke(
            String agentDid, String grantType, String credentialId, Instant revokedAt) {
        if (revokedAt == null) {
            return CompletableFuture.failedFuture(
                    new IllegalArgumentException("AEP credential revocation requires a time."));
        }
        StoredRecord record = records.get(credentialId);
        if (record != null
                && record.agentDid().equals(agentDid)
                && record.grantType().equals(grantType)) {
            records.put(credentialId, record.revoked(revokedAt));
        }
        return completed(null);
    }

    @Override
    public synchronized CompletionStage<Void> revokeGrantType(String agentDid, String grantType, Instant revokedAt) {
        if (revokedAt == null) {
            return CompletableFuture.failedFuture(
                    new IllegalArgumentException("AEP credential revocation requires a time."));
        }
        records.replaceAll((credentialId, record) ->
                record.agentDid().equals(agentDid) && record.grantType().equals(grantType)
                        ? record.revoked(revokedAt)
                        : record);
        return completed(null);
    }

    @Override
    public synchronized CompletionStage<Void> save(ServiceCredentialRecord record) {
        StoredRecord stored;
        try {
            stored = stored(record);
        } catch (RuntimeException exception) {
            return CompletableFuture.failedFuture(exception);
        }
        // Expired and revoked identifiers remain reserved: AEP forbids reassignment.
        if (records.containsKey(record.credentialId())) {
            return CompletableFuture.failedFuture(
                    new IllegalArgumentException("AEP credential identifier has already been issued."));
        }
        boolean reused = records.values().stream()
                .anyMatch(existing -> existing.grantType().equals(stored.grantType())
                        && existing.header().equalsIgnoreCase(stored.header())
                        && MessageDigest.isEqual(existing.verifier(), stored.verifier()));
        if (reused) {
            return CompletableFuture.failedFuture(
                    new IllegalArgumentException("AEP credential secret has already been issued."));
        }
        records.put(record.credentialId(), stored);
        return completed(null);
    }

    private static StoredRecord stored(ServiceCredentialRecord record) {
        GrantResponses.BuiltIn credential =
                AepJson.parseBuiltInGrantResponse(record.grantType(), AepJson.write(record.credential()));
        Instant credentialExpiry = Instant.parse(credential.expiresAt());
        if (record.agentDid().isBlank()
                || record.credentialId().isBlank()
                || !record.expiresAt().isAfter(record.createdAt())
                || !record.credentialId().equals(credential.credentialId())
                || !record.expiresAt().equals(credentialExpiry)) {
            throw new IllegalArgumentException("AEP credential store received an invalid record.");
        }
        if (credential instanceof GrantResponses.OAuthBearer bearer) {
            return record(record, AUTHORIZATION, bearer.accessToken(), bearer.scopes());
        }
        if (credential instanceof GrantResponses.ApiKey apiKey) {
            // APK-CFG-003 asks Services to publish lowercase header names, and the wire comparison is
            // case-insensitive either way, so one canonical spelling is what gets stored.
            return record(record, apiKey.header().toLowerCase(Locale.ROOT), apiKey.apiKey(), apiKey.scopes());
        }
        if (credential instanceof GrantResponses.Basic basic) {
            String plain = basic.username() + ':' + basic.password();
            String encoded = Base64.getEncoder().encodeToString(plain.getBytes(StandardCharsets.UTF_8));
            return record(record, AUTHORIZATION, encoded, basic.scopes());
        }
        throw new IllegalArgumentException("AEP credential store requires a built-in credential.");
    }

    private static StoredRecord record(
            ServiceCredentialRecord source, String header, String secret, List<String> scopes) {
        return new StoredRecord(
                source.agentDid(),
                source.credentialId(),
                source.expiresAt(),
                source.grantType(),
                header,
                null,
                scopes,
                digest(secret));
    }

    private synchronized List<String> apiKeyHeaders() {
        return records.values().stream()
                .filter(record -> Aep.GRANT_TYPE_API_KEY.equals(record.grantType()))
                .map(StoredRecord::header)
                .distinct()
                .toList();
    }

    private static List<Presentation> presentations(String grantType, Map<String, List<String>> headers) {
        if (Aep.GRANT_TYPE_API_KEY.equals(grantType)) return new ArrayList<>();
        AuthorizationScheme expected =
                Aep.GRANT_TYPE_BASIC.equals(grantType) ? AuthorizationScheme.BASIC : AuthorizationScheme.BEARER;
        List<Presentation> result = new ArrayList<>();
        addAuthorizationPresentations(result, headers, AUTHORIZATION, AuthorizationCarrier.STANDARD, expected);
        addAuthorizationPresentations(
                result, headers, Aep.AUTHORIZATION_HEADER, AuthorizationCarrier.DEDICATED, expected);
        return result;
    }

    // OAB-PRS-003 and BSC-PRS-003 make both carriers acceptable on a protected resource, and
    // OAB-PRS-002/BSC-PRS-002 keep the field value identical between them: only the field the value
    // travels in changes. Bearer and Basic records are stored under the canonical Authorization slot,
    // so a presentation is filed there whichever carrier delivered it. Filing it under the request
    // field name instead meant an AEP-Authorization credential matched no record and every
    // dedicated-carrier request came back not_recognized.
    private static void addAuthorizationPresentations(
            List<Presentation> result,
            Map<String, List<String>> headers,
            String field,
            AuthorizationCarrier carrier,
            AuthorizationScheme expected) {
        for (String value : headerValues(headers, field)) {
            try {
                ProtectedResourceAuthorization parsed = AepHttp.parseAuthorization(value, carrier);
                if (parsed.scheme() == expected) {
                    result.add(new Presentation(AUTHORIZATION, parsed.credentials()));
                }
            } catch (IllegalArgumentException ignored) {
                // Another authentication method owns unrecognized field values.
            }
        }
    }

    private static List<Presentation> apiKeyPresentations(Map<String, List<String>> headers, String header) {
        return headerValues(headers, header).stream()
                .map(value -> new Presentation(header, value))
                .toList();
    }

    private static List<String> headerValues(Map<String, List<String>> headers, String name) {
        List<String> values = new ArrayList<>();
        headers.forEach((candidate, candidateValues) -> {
            if (candidate.equalsIgnoreCase(name)) values.addAll(candidateValues);
        });
        return values;
    }

    private static byte[] digest(String value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable.", exception);
        }
    }

    private static <T> CompletionStage<T> completed(T value) {
        return CompletableFuture.completedFuture(value);
    }

    private record Presentation(String header, String value) {}

    private record StoredRecord(
            String agentDid,
            String credentialId,
            Instant expiresAt,
            String grantType,
            String header,
            Instant revokedAt,
            List<String> scopes,
            byte[] verifier) {
        private StoredRecord {
            scopes = List.copyOf(scopes);
            verifier = verifier.clone();
        }

        @Override
        public byte[] verifier() {
            return verifier.clone();
        }

        private StoredRecord revoked(Instant value) {
            return new StoredRecord(agentDid, credentialId, expiresAt, grantType, header, value, scopes, verifier);
        }
    }
}
