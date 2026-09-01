package foundation.aep.core;

import java.time.Duration;
import java.util.List;

/** Protocol-wide constants. */
public final class Aep {
    public static final String VERSION = "1.0";
    public static final String MEDIA_TYPE = "application/aep+json";
    public static final String PROBLEM_MEDIA_TYPE = "application/problem+json";
    public static final String AUTHENTICATION_SCHEME = "AEP";
    public static final String AUTHORIZATION_HEADER = "AEP-Authorization";
    public static final String WELL_KNOWN_PATH = "/.well-known/aep";
    public static final String DEFAULT_ENDPOINT_BASE = "/aep/";
    public static final String IDENTITY_METHOD_DID_WEB = "did:web";
    public static final String AUTHENTICATION_METHOD_JWT = "aep-jwt";
    public static final String CLAIM_CONTACT_ADDRESS_PRIMARY = "contact.address.primary";
    public static final String CLAIM_CONTACT_EMAIL = "contact.email";
    public static final String CLAIM_CONTACT_MOBILE = "contact.mobile";
    public static final String CLAIM_PERSON_BIRTHDATE = "person.birthdate";
    public static final String CLAIM_PERSON_FIRST_NAME = "person.first_name";
    public static final String CLAIM_PERSON_LAST_NAME = "person.last_name";
    public static final String CLAIM_PERSON_USERNAME = "person.username";
    public static final String GRANT_TYPE_API_KEY = "api-key";
    public static final String GRANT_TYPE_BASIC = "basic";
    public static final String GRANT_TYPE_OAUTH_BEARER = "oauth-bearer";
    public static final Duration MAX_ASSERTION_LIFETIME = Duration.ofMinutes(5);
    public static final Duration RECOMMENDED_CLOCK_SKEW = Duration.ofSeconds(30);
    public static final List<String> REQUIRED_SIGNING_ALGORITHMS = List.of("EdDSA", "ES256");
    public static final List<String> REGISTERED_CLAIMS = List.of(
            CLAIM_CONTACT_ADDRESS_PRIMARY,
            CLAIM_CONTACT_EMAIL,
            CLAIM_CONTACT_MOBILE,
            CLAIM_PERSON_BIRTHDATE,
            CLAIM_PERSON_FIRST_NAME,
            CLAIM_PERSON_LAST_NAME,
            CLAIM_PERSON_USERNAME);
    public static final List<String> BUILT_IN_GRANT_TYPES =
            List.of(GRANT_TYPE_OAUTH_BEARER, GRANT_TYPE_API_KEY, GRANT_TYPE_BASIC);

    private Aep() {}
}
