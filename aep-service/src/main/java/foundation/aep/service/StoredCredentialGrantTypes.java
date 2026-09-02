package foundation.aep.service;

import foundation.aep.core.Aep;
import foundation.aep.core.AepJson;
import foundation.aep.core.AepValidation;
import foundation.aep.core.GrantRequest;
import foundation.aep.core.GrantResponses;
import foundation.aep.core.InspectDocument;
import foundation.aep.core.RevokeRequest;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletionStage;

public final class StoredCredentialGrantTypes {
    private StoredCredentialGrantTypes() {}

    public static StoredCredentialGrantType oauthBearer(
            InspectDocument.GrantTypeConfig config,
            BuiltInCredentialIssuer<GrantResponses.OAuthBearer> issuer,
            ServiceCredentialStore store) {
        return create(Aep.GRANT_TYPE_OAUTH_BEARER, config, issuer, store);
    }

    public static StoredCredentialGrantType apiKey(
            InspectDocument.GrantTypeConfig config,
            BuiltInCredentialIssuer<GrantResponses.ApiKey> issuer,
            ServiceCredentialStore store) {
        return create(Aep.GRANT_TYPE_API_KEY, config, issuer, store);
    }

    public static StoredCredentialGrantType basic(
            InspectDocument.GrantTypeConfig config,
            BuiltInCredentialIssuer<GrantResponses.Basic> issuer,
            ServiceCredentialStore store) {
        return create(Aep.GRANT_TYPE_BASIC, config, issuer, store);
    }

    private static <T extends GrantResponses.BuiltIn> StoredCredentialGrantType create(
            String grantType,
            InspectDocument.GrantTypeConfig config,
            BuiltInCredentialIssuer<T> issuer,
            ServiceCredentialStore store) {
        Objects.requireNonNull(issuer, "issuer");
        Objects.requireNonNull(store, "store");
        StoredHandler<T> handler = new StoredHandler<>(grantType, config, issuer, store);
        return new StoredCredentialGrantType(grantType, config, new GrantTypeDefinition(grantType, handler), handler);
    }

    private static final class StoredHandler<T extends GrantResponses.BuiltIn>
            implements GrantTypeHandler, CredentialAuthenticator {
        private final String grantType;
        private final InspectDocument.GrantTypeConfig config;
        private final BuiltInCredentialIssuer<T> issuer;
        private final ServiceCredentialStore store;

        private StoredHandler(
                String grantType,
                InspectDocument.GrantTypeConfig config,
                BuiltInCredentialIssuer<T> issuer,
                ServiceCredentialStore store) {
            this.grantType = grantType;
            this.config = config;
            this.issuer = issuer;
            this.store = store;
        }

        @Override
        public CompletionStage<GrantResult> grant(GrantRequest request, GrantContext context) {
            return issuer.issue(request, context).thenCompose(credential -> {
                requireIssuedCredential(credential, context.now());
                ServiceCredentialRecord record = credentialRecord(credential, context);
                return store.save(record)
                        .thenApply(ignored -> new GrantResult(
                                credential.credentialId(),
                                AepJson.parseObject(AepJson.write(credential), "Grant response")));
            });
        }

        @Override
        public CompletionStage<Void> revoke(RevokeRequest request, RevokeContext context) {
            if (request.credentialId() != null) {
                return store.revoke(context.agentDid(), grantType, request.credentialId(), context.now());
            }
            return store.revokeGrantType(context.agentDid(), grantType, context.now());
        }

        @Override
        public CompletionStage<Boolean> hasPresentation(CredentialAuthenticationInput input) {
            return store.hasPresentation(grantType, input);
        }

        @Override
        public CompletionStage<Optional<AuthenticatedPrincipal>> authenticate(CredentialAuthenticationInput input) {
            return store.authenticate(grantType, input)
                    .thenApply(match -> match.map(value -> {
                        if (value.agentDid() == null
                                || value.agentDid().isBlank()
                                || value.credentialId() == null
                                || value.credentialId().isBlank()
                                || !value.expiresAt().isAfter(input.now())
                                || !grantType.equals(value.grantType())) {
                            throw new IllegalArgumentException("AEP credential store returned an invalid match.");
                        }
                        return new AuthenticatedPrincipal(
                                value.agentDid(),
                                grantType,
                                value.credentialId(),
                                grantType,
                                value.scopes(),
                                AuthenticatedPrincipal.Kind.SESSION_CREDENTIAL);
                    }));
        }

        private void requireIssuedCredential(T credential, Instant issuedAt) {
            if (!AepValidation.grantResponse(credential).isEmpty()) {
                throw new IllegalArgumentException("AEP issuer returned an invalid Grant response.");
            }
            Instant expiresAt;
            try {
                expiresAt = Instant.parse(credential.expiresAt());
            } catch (DateTimeParseException exception) {
                throw new IllegalArgumentException("AEP issued credential expiry is invalid.", exception);
            }
            if (!expiresAt.isAfter(issuedAt)) {
                throw new IllegalArgumentException("AEP issued credential must expire after issuance.");
            }
            if (credential instanceof GrantResponses.ApiKey apiKey
                    && config != null
                    && config.headerNames() != null
                    && !config.headerNames().isEmpty()
                    && config.headerNames().stream().noneMatch(header -> header.equalsIgnoreCase(apiKey.header()))) {
                throw new IllegalArgumentException("AEP issued API-key header is not advertised by the Service.");
            }
        }

        private ServiceCredentialRecord credentialRecord(T credential, GrantContext context) {
            Instant expiresAt = Instant.parse(credential.expiresAt());
            return new ServiceCredentialRecord(
                    context.agentDid(), context.now(), credential, credential.credentialId(), expiresAt, grantType);
        }
    }
}
