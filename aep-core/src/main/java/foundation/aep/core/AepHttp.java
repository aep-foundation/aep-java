package foundation.aep.core;

import java.net.URI;
import java.util.Locale;
import java.util.Map;

public final class AepHttp {
    private AepHttp() {}

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
        int separator = value.indexOf(' ');
        if (separator <= 0 || separator == value.length() - 1) {
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
        String credentials = value.substring(separator + 1);
        if (credentials.isBlank() || Character.isWhitespace(credentials.charAt(0))) {
            throw unrecognizedAuthorization();
        }
        return new ProtectedResourceAuthorization(carrier, parsed, credentials);
    }

    private static AepAuthorizationException unrecognizedAuthorization() {
        return new AepAuthorizationException("not_recognized", "The authorization presentation was not recognized.");
    }
}
