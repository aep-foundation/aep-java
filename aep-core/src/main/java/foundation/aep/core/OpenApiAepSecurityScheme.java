package foundation.aep.core;

import com.fasterxml.jackson.annotation.JsonProperty;

public record OpenApiAepSecurityScheme(
        @JsonProperty("x-aep-authentication-method") String authenticationMethod) {}
