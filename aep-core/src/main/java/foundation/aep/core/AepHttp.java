package foundation.aep.core;

import java.net.URI;
import java.util.Locale;
import java.util.Map;

public final class AepHttp {
    private AepHttp() {}

    /**
     * Reports whether a credential is the visible US-ASCII the AEP, Bearer, and Basic grammars
     * share. Anything else, notably a control character or an embedded CRLF, would travel back
     * into a request header through {@link #renderAuthorization}.
     */
    private static boolean isCredentialToken(String value) {
        if (value.isEmpty()) {
            return false;
        }
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (character < 0x21 || character > 0x7e) {
                return false;
            }
        }
        return true;
    }

    public static String normalizeEndpointBase(String endpointBase) {
        String value = endpointBase == null ? Aep.DEFAULT_ENDPOINT_BASE : endpointBase;
        if (!value.startsWith("/") || value.startsWith("//")) {
            throw new IllegalArgumentException("AEP endpoint_base must be an absolute path.");
        }
        URI reference = URI.create(value);
        if (reference.getRawQuery() != null || reference.getRawFragment() != null) {
            throw new IllegalArgumentException("AEP endpoint_base must not contain a query or fragment.");
        }
        return value.endsWith("/") ? value : value + "/";
    }

    public static String commandPath(AepCommand command, String endpointBase) {
        if (command == AepCommand.INSPECT) {
            throw new IllegalArgumentException("Inspect uses the AEP well-known path.");
        }
        return normalizeEndpointBase(endpointBase) + command.value();
    }

    public static URI commandUri(URI origin, AepCommand command, String endpointBase) {
        return origin.resolve(commandPath(command, endpointBase));
    }

    public static String authorizationHeaderName(AuthorizationCarrier carrier) {
        if (carrier == null) {
            throw new IllegalArgumentException("Authorization carrier is required.");
        }
        return carrier.value();
    }

    public static Map<String, String> renderAuthorization(ProtectedResourceAuthorization value) {
        if (value == null || value.carrier() == null || value.scheme() == null) {
            throw new AepAuthorizationException("invalid_request", "Authorization presentation is incomplete.");
        }
        if (value.credentials() == null || value.credentials().isEmpty()) {
            throw new AepAuthorizationException("invalid_request", "Authorization credentials must not be empty.");
        }
        if (!isCredentialToken(value.credentials())) {
            throw new AepAuthorizationException(
                    "invalid_request", "Authorization credentials must be visible US-ASCII.");
        }
        return Map.of(authorizationHeaderName(value.carrier()), value.scheme().value() + " " + value.credentials());
    }

    public static ProtectedResourceAuthorization parseAuthorization(String value, AuthorizationCarrier carrier) {
        if (carrier == null) {
            throw new IllegalArgumentException("Authorization carrier is required.");
        }
        if (value == null) {
            throw unrecognizedAuthorization();
        }
        if (carrier == AuthorizationCarrier.DEDICATED && value.indexOf(',') >= 0) {
            throw new AepAuthorizationException("not_recognized", "The dedicated authorization field is ambiguous.");
        }
        int separator = separatorIndex(value);
        if (separator <= 0) {
            throw unrecognizedAuthorization();
        }
        String scheme = value.substring(0, separator).toLowerCase(Locale.ROOT);
        AuthorizationScheme parsed =
                switch (scheme) {
                    case "aep" -> AuthorizationScheme.AEP;
                    case "bearer" -> AuthorizationScheme.BEARER;
                    case "basic" -> AuthorizationScheme.BASIC;
                    default -> throw unrecognizedAuthorization();
                };
        // CORE-AUTH-001 spells the separator as 1*SP, so repeated spaces belong to the grammar
        // rather than marking a malformed presentation, and a field value may carry trailing
        // optional whitespace that the sender is entitled to add.
        String credentials = trimOptionalWhitespace(value.substring(separator));
        if (!isCredentialToken(credentials)) {
            throw unrecognizedAuthorization();
        }
        return new ProtectedResourceAuthorization(carrier, parsed, credentials);
    }

    private static int separatorIndex(String value) {
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (character == ' ' || character == '\t') {
                return index;
            }
        }
        return -1;
    }

    private static String trimOptionalWhitespace(String value) {
        int start = 0;
        int end = value.length();
        while (start < end && (value.charAt(start) == ' ' || value.charAt(start) == '\t')) {
            start++;
        }
        while (end > start && (value.charAt(end - 1) == ' ' || value.charAt(end - 1) == '\t')) {
            end--;
        }
        return value.substring(start, end);
    }

    private static AepAuthorizationException unrecognizedAuthorization() {
        return new AepAuthorizationException("not_recognized", "The authorization presentation was not recognized.");
    }
}
