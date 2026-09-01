package foundation.aep.core;

public record ProtectedResourceAuthorization(
        AuthorizationCarrier carrier, AuthorizationScheme scheme, String credentials) {
    @Override
    public String toString() {
        return "ProtectedResourceAuthorization[carrier=" + carrier + ", scheme=" + scheme + ", credentials=<redacted>]";
    }
}
