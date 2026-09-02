package foundation.aep.core;

import com.fasterxml.jackson.annotation.JsonProperty;

public record PlatformProvisionRequest(
        @JsonProperty("service_did") String serviceDid) {}
