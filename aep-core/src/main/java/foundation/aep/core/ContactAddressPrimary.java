package foundation.aep.core;

import com.fasterxml.jackson.annotation.JsonProperty;

public record ContactAddressPrimary(
        String city,
        String country,
        @JsonProperty("first_name") String firstName,
        @JsonProperty("last_name") String lastName,
        String line1,
        String line2,
        String line3,
        String postcode,
        String region) {}
