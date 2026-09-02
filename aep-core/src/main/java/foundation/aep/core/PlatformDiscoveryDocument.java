package foundation.aep.core;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public record PlatformDiscoveryDocument(
        @JsonProperty("aep_version") String version,
        Endpoints endpoints,
        Http http,
        Identity identity,
        Platform platform,
        Signing signing) {
    public record Endpoints(
            @JsonProperty("hosted_verification") String hostedVerification,
            String lifecycle,
            String list,
            String provision,
            String sign) {}

    public record Http(@JsonProperty("endpoint_base") String endpointBase) {}

    public record Identity(
            @JsonProperty("did_methods") List<String> didMethods,
            @JsonProperty("did_url_template") String didUrlTemplate) {
        public Identity {
            didMethods = Copies.list(didMethods);
        }

        @Override
        public List<String> didMethods() {
            return List.copyOf(didMethods);
        }
    }

    public record Platform(
            String did, @JsonProperty("hosted_verification") boolean hostedVerification, String name) {}

    public record Signing(
            List<String> algorithms,
            @JsonProperty("default_lifetime_seconds") String defaultLifetimeSeconds) {
        public Signing {
            algorithms = Copies.list(algorithms);
        }

        @Override
        public List<String> algorithms() {
            return List.copyOf(algorithms);
        }
    }
}
