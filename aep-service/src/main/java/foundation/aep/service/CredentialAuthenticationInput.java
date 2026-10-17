package foundation.aep.service;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;

public record CredentialAuthenticationInput(Map<String, List<String>> headers, String method, URI url, Instant now) {
    public CredentialAuthenticationInput {
        headers = ServiceCopies.headers(headers);
    }

    @Override
    public Map<String, List<String>> headers() {
        return ServiceCopies.headers(headers);
    }

    // Every request header reaches this record, so a generated toString would print the Authorization
    // field value, the API-key field value, and base64(username:password) verbatim into whatever log
    // a third-party authenticator or credential store keeps. The header names alone carry no secret.
    @Override
    public String toString() {
        return "CredentialAuthenticationInput[headerNames=" + headers.keySet() + ", method=" + method + ", url=" + url
                + ", now=" + now + "]";
    }
}
