package foundation.aep.core;

import com.fasterxml.jackson.annotation.JsonProperty;

public record PlatformVerificationRequest(
        @JsonProperty("client_assertion") String clientAssertion,
        @JsonProperty("op") AssertionOperation operation,
        String resource,
        @JsonProperty("service_did") String serviceDid) {}
