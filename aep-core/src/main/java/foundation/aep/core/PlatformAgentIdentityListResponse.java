package foundation.aep.core;

import java.util.List;

public record PlatformAgentIdentityListResponse(String count, List<PlatformAgentIdentity> data, String total) {
    public PlatformAgentIdentityListResponse {
        data = Copies.list(data);
    }

    @Override
    public List<PlatformAgentIdentity> data() {
        return List.copyOf(data);
    }
}
