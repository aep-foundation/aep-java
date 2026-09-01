package foundation.aep.core;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import java.util.Map;

public final class InspectDocument {
    private final String documentVersion;
    private final Authentication documentAuthentication;
    private final Bindings documentBindings;
    private final Claims documentClaims;
    private final Commands documentCommands;
    private final Core documentCore;
    private final Extensions documentExtensions;
    private final Http documentHttp;
    private final Identity documentIdentity;
    private final Service documentService;

    private InspectDocument(Builder builder) {
        documentVersion = builder.configuredVersion;
        documentAuthentication = builder.configuredAuthentication;
        documentBindings = builder.configuredBindings;
        documentClaims = builder.configuredClaims;
        documentCommands = builder.configuredCommands;
        documentCore = builder.configuredCore;
        documentExtensions = builder.configuredExtensions;
        documentHttp = builder.configuredHttp;
        documentIdentity = builder.configuredIdentity;
        documentService = builder.configuredService;
    }

    public static Builder builder() {
        return new Builder();
    }

    @JsonProperty("aep_version")
    public String version() {
        return documentVersion;
    }

    @JsonProperty("authentication")
    public Authentication authentication() {
        return documentAuthentication;
    }

    @JsonProperty("bindings")
    public Bindings bindings() {
        return documentBindings;
    }

    @JsonProperty("claims")
    public Claims claims() {
        return documentClaims;
    }

    @JsonProperty("commands")
    public Commands commands() {
        return documentCommands;
    }

    @JsonProperty("core")
    public Core core() {
        return documentCore;
    }

    @JsonProperty("extensions")
    public Extensions extensions() {
        return documentExtensions;
    }

    @JsonProperty("http")
    public Http http() {
        return documentHttp;
    }

    @JsonProperty("identity")
    public Identity identity() {
        return documentIdentity;
    }

    @JsonProperty("service")
    public Service service() {
        return documentService;
    }

    public record Authentication(List<String> methods) {
        public Authentication {
            methods = Copies.list(methods);
        }
    }

    public record Bindings(List<String> supported) {
        public Bindings {
            supported = Copies.list(supported);
        }
    }

    public record Claims(List<String> required, List<String> preferred, List<String> optional) {
        public Claims {
            required = Copies.list(required);
            preferred = Copies.list(preferred);
            optional = Copies.list(optional);
        }
    }

    public record Commands(
            List<String> supported,
            @JsonProperty("grant_types") List<String> grantTypes,
            @JsonProperty("grant_types_config") Map<String, GrantTypeConfig> grantTypesConfig) {
        public Commands {
            supported = Copies.list(supported);
            grantTypes = Copies.list(grantTypes);
            grantTypesConfig = Copies.map(grantTypesConfig);
        }
    }

    public record GrantTypeConfig(
            @JsonProperty("supports_per_credential_revoke") String supportsPerCredentialRevoke) {}

    public record Core(@JsonProperty("signing_algorithms") List<String> signingAlgorithms) {
        public Core {
            signingAlgorithms = Copies.list(signingAlgorithms);
        }
    }

    public record Extensions(List<String> supported) {
        public Extensions {
            supported = Copies.list(supported);
        }
    }

    public record Http(@JsonProperty("endpoint_base") String endpointBase, OpenApi openapi) {}

    public record OpenApi(
            String url, @JsonProperty("path_matching") PathMatching pathMatching) {}

    public record PathMatching(
            @JsonProperty("trailing_slash") String trailingSlash) {}

    public record Identity(List<String> methods) {
        public Identity {
            methods = Copies.list(methods);
        }
    }

    public record Service(String did) {}

    public static final class Builder {
        private String configuredVersion;
        private Authentication configuredAuthentication;
        private Bindings configuredBindings;
        private Claims configuredClaims;
        private Commands configuredCommands;
        private Core configuredCore;
        private Extensions configuredExtensions;
        private Http configuredHttp;
        private Identity configuredIdentity;
        private Service configuredService;

        private Builder() {}

        @JsonProperty("aep_version")
        public Builder version(String value) {
            configuredVersion = value;
            return this;
        }

        public Builder authentication(Authentication value) {
            configuredAuthentication = value;
            return this;
        }

        public Builder bindings(Bindings value) {
            configuredBindings = value;
            return this;
        }

        public Builder claims(Claims value) {
            configuredClaims = value;
            return this;
        }

        public Builder commands(Commands value) {
            configuredCommands = value;
            return this;
        }

        public Builder core(Core value) {
            configuredCore = value;
            return this;
        }

        public Builder extensions(Extensions value) {
            configuredExtensions = value;
            return this;
        }

        public Builder http(Http value) {
            configuredHttp = value;
            return this;
        }

        public Builder identity(Identity value) {
            configuredIdentity = value;
            return this;
        }

        public Builder service(Service value) {
            configuredService = value;
            return this;
        }

        public InspectDocument build() {
            return new InspectDocument(this);
        }
    }
}
