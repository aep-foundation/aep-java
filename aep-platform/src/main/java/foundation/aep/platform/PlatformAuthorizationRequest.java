package foundation.aep.platform;

import foundation.aep.core.PlatformLifecycleRequest;
import foundation.aep.core.PlatformProvisionRequest;
import foundation.aep.core.PlatformSignRequest;
import foundation.aep.core.PlatformVerificationRequest;

public final class PlatformAuthorizationRequest {
    private final PlatformAuthorizationOperation requestedOperation;
    private final PlatformIdentityRecord requestedIdentity;
    private final PlatformIdentityListQuery requestedListQuery;
    private final PlatformProvisionRequest requestedProvision;
    private final PlatformSignRequest requestedSign;
    private final PlatformLifecycleRequest requestedLifecycle;
    private final PlatformVerificationRequest requestedVerification;

    private PlatformAuthorizationRequest(
            PlatformAuthorizationOperation operation,
            PlatformIdentityRecord identity,
            PlatformIdentityListQuery listQuery,
            PlatformProvisionRequest provisionRequest,
            PlatformSignRequest signRequest,
            PlatformLifecycleRequest lifecycleRequest,
            PlatformVerificationRequest verificationRequest) {
        requestedOperation = java.util.Objects.requireNonNull(operation, "operation");
        requestedIdentity = identity;
        requestedListQuery = listQuery;
        requestedProvision = provisionRequest;
        requestedSign = signRequest;
        requestedLifecycle = lifecycleRequest;
        requestedVerification = verificationRequest;
    }

    public static PlatformAuthorizationRequest getIdentity(PlatformIdentityRecord identity) {
        return new PlatformAuthorizationRequest(
                PlatformAuthorizationOperation.GET_IDENTITY, identity, null, null, null, null, null);
    }

    public static PlatformAuthorizationRequest list(PlatformIdentityListQuery query) {
        return new PlatformAuthorizationRequest(
                PlatformAuthorizationOperation.LIST_IDENTITIES, null, query, null, null, null, null);
    }

    public static PlatformAuthorizationRequest provision(PlatformProvisionRequest request) {
        return new PlatformAuthorizationRequest(
                PlatformAuthorizationOperation.PROVISION_IDENTITY, null, null, request, null, null, null);
    }

    public static PlatformAuthorizationRequest sign(PlatformIdentityRecord identity, PlatformSignRequest request) {
        return new PlatformAuthorizationRequest(
                PlatformAuthorizationOperation.SIGN, identity, null, null, request, null, null);
    }

    public static PlatformAuthorizationRequest update(
            PlatformIdentityRecord identity, PlatformLifecycleRequest request) {
        return new PlatformAuthorizationRequest(
                PlatformAuthorizationOperation.UPDATE_IDENTITY, identity, null, null, null, request, null);
    }

    public static PlatformAuthorizationRequest verify(
            PlatformIdentityRecord identity, PlatformVerificationRequest request) {
        return new PlatformAuthorizationRequest(
                PlatformAuthorizationOperation.VERIFY, identity, null, null, null, null, request);
    }

    public PlatformAuthorizationOperation operation() {
        return requestedOperation;
    }

    public PlatformIdentityRecord identity() {
        return requestedIdentity;
    }

    public PlatformIdentityListQuery listQuery() {
        return requestedListQuery;
    }

    public PlatformProvisionRequest provisionRequest() {
        return requestedProvision;
    }

    public PlatformSignRequest signRequest() {
        return requestedSign;
    }

    public PlatformLifecycleRequest lifecycleRequest() {
        return requestedLifecycle;
    }

    public PlatformVerificationRequest verificationRequest() {
        return requestedVerification;
    }
}
