package foundation.aep.platform;

import foundation.aep.core.ManagedAgentStatus;

public record PlatformIdentityListQuery(
        boolean descending, int limit, int offset, String serviceDid, ManagedAgentStatus status) {
    public static PlatformIdentityListQuery defaults() {
        return new PlatformIdentityListQuery(false, 100, 0, null, null);
    }
}
