package foundation.aep.service;

public record AepHttpAuthenticationResult(
        boolean authenticated, AuthenticatedPrincipal principal, AepHttpResponse response) {
    public AepHttpAuthenticationResult {
        if (authenticated) {
            if (principal == null || response != null) {
                throw new IllegalArgumentException("Authenticated results require only a principal.");
            }
        } else {
            if (response == null || principal != null) {
                throw new IllegalArgumentException("Rejected results require only a response.");
            }
        }
    }

    public static AepHttpAuthenticationResult authenticated(AuthenticatedPrincipal principal) {
        return new AepHttpAuthenticationResult(true, principal, null);
    }

    public static AepHttpAuthenticationResult rejected(AepHttpResponse response) {
        return new AepHttpAuthenticationResult(false, null, response);
    }
}
