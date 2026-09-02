package foundation.aep.service;

public record ProtectedResourceResult(
        boolean authenticated, AuthenticatedPrincipal principal, ServiceResponse<?> response) {
    public static ProtectedResourceResult authenticated(AuthenticatedPrincipal principal) {
        return new ProtectedResourceResult(true, principal, null);
    }

    public static ProtectedResourceResult rejected(ServiceResponse<?> response) {
        return new ProtectedResourceResult(false, null, response);
    }
}
