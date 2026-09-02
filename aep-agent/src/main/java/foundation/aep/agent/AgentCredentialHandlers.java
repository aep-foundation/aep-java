package foundation.aep.agent;

import foundation.aep.core.Aep;
import foundation.aep.core.AepJson;
import foundation.aep.core.GrantResponses;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Base64;
import java.util.List;
import java.util.Map;

public final class AgentCredentialHandlers {
    private AgentCredentialHandlers() {}

    public static List<AgentCredentialHandler> builtIn() {
        return List.of(oauthBearer(), apiKey(), basic());
    }

    public static AgentCredentialHandler oauthBearer() {
        return new BuiltInHandler(Aep.GRANT_TYPE_OAUTH_BEARER);
    }

    public static AgentCredentialHandler apiKey() {
        return new BuiltInHandler(Aep.GRANT_TYPE_API_KEY);
    }

    public static AgentCredentialHandler basic() {
        return new BuiltInHandler(Aep.GRANT_TYPE_BASIC);
    }

    private static final class BuiltInHandler implements AgentCredentialHandler {
        private final String credentialGrantType;

        private BuiltInHandler(String value) {
            credentialGrantType = value;
        }

        @Override
        public String authenticationMethod() {
            return credentialGrantType;
        }

        @Override
        public String grantType() {
            return credentialGrantType;
        }

        @Override
        public AgentCredential parse(String serviceDid, String responseJson) {
            GrantResponses.BuiltIn credential = AepJson.parseBuiltInGrantResponse(credentialGrantType, responseJson);
            Instant expiresAt;
            try {
                expiresAt = Instant.parse(credential.expiresAt());
            } catch (DateTimeParseException exception) {
                throw new IllegalArgumentException("AEP credential expiry is invalid.", exception);
            }
            return new AgentCredential(
                    serviceDid, credentialGrantType, credential.credentialId(), expiresAt, responseJson);
        }

        @Override
        public Map<String, String> authorizationHeaders(AgentCredential record, URI resource) {
            GrantResponses.BuiltIn credential = requireMatchingCredential(record);
            if (credential instanceof GrantResponses.OAuthBearer bearer) {
                return Map.of("Authorization", "Bearer " + bearer.accessToken());
            }
            if (credential instanceof GrantResponses.ApiKey apiKey) {
                return Map.of(apiKey.header(), apiKey.apiKey());
            }
            if (credential instanceof GrantResponses.Basic basic) {
                String value = basic.username() + ':' + basic.password();
                String encoded = Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8));
                return Map.of("Authorization", "Basic " + encoded);
            }
            throw new IllegalArgumentException("Unsupported built-in AEP credential.");
        }

        private GrantResponses.BuiltIn requireMatchingCredential(AgentCredential record) {
            if (!credentialGrantType.equals(record.grantType())) {
                throw new IllegalArgumentException("Stored AEP credential has the wrong Grant Type.");
            }
            GrantResponses.BuiltIn credential =
                    AepJson.parseBuiltInGrantResponse(credentialGrantType, record.responseJson());
            Instant expiresAt = Instant.parse(credential.expiresAt());
            if (!credential.credentialId().equals(record.credentialId()) || !expiresAt.equals(record.expiresAt())) {
                throw new IllegalArgumentException("Stored AEP credential metadata does not match its payload.");
            }
            return credential;
        }
    }
}
