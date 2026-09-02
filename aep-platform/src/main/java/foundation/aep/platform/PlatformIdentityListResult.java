package foundation.aep.platform;

import java.util.List;

public record PlatformIdentityListResult(List<PlatformIdentityRecord> identities, int total) {
    public PlatformIdentityListResult {
        identities = List.copyOf(identities);
        if (total < identities.size()) throw new IllegalArgumentException("total must include every returned identity");
    }

    @Override
    public List<PlatformIdentityRecord> identities() {
        return List.copyOf(identities);
    }
}
