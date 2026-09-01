package foundation.aep.core;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.LinkedHashMap;
import java.util.Map;

public final class ClaimValues {
    private final ContactAddressPrimary addressClaim;
    private final String emailClaim;
    private final String mobileClaim;
    private final String birthdateClaim;
    private final String firstNameClaim;
    private final String lastNameClaim;
    private final String usernameClaim;
    private final Map<String, Object> additionalClaims;

    private ClaimValues(Builder builder) {
        addressClaim = builder.configuredAddress;
        emailClaim = builder.configuredEmail;
        mobileClaim = builder.configuredMobile;
        birthdateClaim = builder.configuredBirthdate;
        firstNameClaim = builder.configuredFirstName;
        lastNameClaim = builder.configuredLastName;
        usernameClaim = builder.configuredUsername;
        additionalClaims = Copies.jsonMap(builder.configuredAdditional);
    }

    public static Builder builder() {
        return new Builder();
    }

    @JsonProperty("contact.address.primary")
    public ContactAddressPrimary contactAddressPrimary() {
        return addressClaim;
    }

    @JsonProperty("contact.email")
    public String contactEmail() {
        return emailClaim;
    }

    @JsonProperty("contact.mobile")
    public String contactMobile() {
        return mobileClaim;
    }

    @JsonProperty("person.birthdate")
    public String personBirthdate() {
        return birthdateClaim;
    }

    @JsonProperty("person.first_name")
    public String personFirstName() {
        return firstNameClaim;
    }

    @JsonProperty("person.last_name")
    public String personLastName() {
        return lastNameClaim;
    }

    @JsonProperty("person.username")
    public String personUsername() {
        return usernameClaim;
    }

    @JsonAnyGetter
    public Map<String, Object> additional() {
        return additionalClaims;
    }

    public boolean contains(String name) {
        return switch (name) {
            case Aep.CLAIM_CONTACT_ADDRESS_PRIMARY -> addressClaim != null;
            case Aep.CLAIM_CONTACT_EMAIL -> emailClaim != null;
            case Aep.CLAIM_CONTACT_MOBILE -> mobileClaim != null;
            case Aep.CLAIM_PERSON_BIRTHDATE -> birthdateClaim != null;
            case Aep.CLAIM_PERSON_FIRST_NAME -> firstNameClaim != null;
            case Aep.CLAIM_PERSON_LAST_NAME -> lastNameClaim != null;
            case Aep.CLAIM_PERSON_USERNAME -> usernameClaim != null;
            default -> additionalClaims.containsKey(name);
        };
    }

    public static final class Builder {
        private ContactAddressPrimary configuredAddress;
        private String configuredEmail;
        private String configuredMobile;
        private String configuredBirthdate;
        private String configuredFirstName;
        private String configuredLastName;
        private String configuredUsername;
        private final Map<String, Object> configuredAdditional = new LinkedHashMap<>();

        private Builder() {}

        @JsonProperty("contact.address.primary")
        public Builder contactAddressPrimary(ContactAddressPrimary value) {
            configuredAddress = value;
            return this;
        }

        @JsonProperty("contact.email")
        public Builder contactEmail(String value) {
            configuredEmail = value;
            return this;
        }

        @JsonProperty("contact.mobile")
        public Builder contactMobile(String value) {
            configuredMobile = value;
            return this;
        }

        @JsonProperty("person.birthdate")
        public Builder personBirthdate(String value) {
            configuredBirthdate = value;
            return this;
        }

        @JsonProperty("person.first_name")
        public Builder personFirstName(String value) {
            configuredFirstName = value;
            return this;
        }

        @JsonProperty("person.last_name")
        public Builder personLastName(String value) {
            configuredLastName = value;
            return this;
        }

        @JsonProperty("person.username")
        public Builder personUsername(String value) {
            configuredUsername = value;
            return this;
        }

        @JsonAnySetter
        public Builder additional(String name, Object value) {
            configuredAdditional.put(name, value);
            return this;
        }

        public ClaimValues build() {
            return new ClaimValues(this);
        }
    }
}
