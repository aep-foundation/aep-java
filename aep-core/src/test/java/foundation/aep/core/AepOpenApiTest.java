package foundation.aep.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.net.URI;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

final class AepOpenApiTest {
    private static final String AEP = "aepScheme";
    private static final String KEY = "apiKeyScheme";

    @Test
    void keepsEncodedSeparatorsInsideTheirPathSegment() {
        assertEquals(
                "/objects/{id}",
                AepOpenApi.matchPath(
                                List.of("/objects/{id}", "/objects/{folder}/{id}"),
                                "get",
                                "https://service.example/objects/a%2Fb?view=full",
                                AepOpenApi.TrailingSlashMode.STRICT)
                        .template());
        assertEquals(
                "/objects/a%2Fb",
                AepOpenApi.matchPath(
                                List.of("/objects/{id}", "/objects/a%2Fb"),
                                "get",
                                "/objects/a%2Fb",
                                AepOpenApi.TrailingSlashMode.STRICT)
                        .template());
    }

    @Test
    void resolvesAnonymousHttpsDocuments() {
        URI inspect = URI.create("https://api.example.com/discovery/aep");

        assertEquals(
                URI.create("https://api.example.com/openapi.json"),
                AepOpenApi.resolveDocumentUri(inspect, "../openapi.json"));
        assertEquals(
                URI.create("https://docs.example.net/openapi.json"),
                AepOpenApi.resolveDocumentUri(inspect, "https://docs.example.net/openapi.json"));
        assertThrows(
                IllegalArgumentException.class,
                () -> AepOpenApi.resolveDocumentUri(inspect, "http://api.example.com/openapi.json"));
        assertThrows(
                IllegalArgumentException.class,
                () -> AepOpenApi.resolveDocumentUri(inspect, "https://user@api.example.com/openapi.json"));
        assertThrows(
                IllegalArgumentException.class,
                () -> AepOpenApi.resolveDocumentUri(inspect, "http://127.0.0.1/openapi.json", true));
    }

    @Test
    void permitsExplicitLoopbackDevelopmentWithoutDowngrades() {
        URI inspect = URI.create("http://127.0.0.1:4100/.well-known/aep");

        assertEquals(
                URI.create("http://127.0.0.1:4100/openapi.json"),
                AepOpenApi.resolveDocumentUri(inspect, "/openapi.json", true));
        assertThrows(IllegalArgumentException.class, () -> AepOpenApi.resolveDocumentUri(inspect, "/openapi.json"));
    }

    @Test
    void selectsTheMostSpecificPathWithoutUsingTheQuery() {
        AepOpenApi.PathMatch match = AepOpenApi.matchPath(
                List.of("/v1/orders/{id}", "/v1/{kind}/123"),
                "get",
                "/v1/orders/123?view=full",
                AepOpenApi.TrailingSlashMode.STRICT);

        assertEquals("GET", match.method());
        assertEquals("/v1/orders/{id}", match.template());
    }

    @Test
    void appliesTrailingSlashPolicyAndRejectsAmbiguity() {
        assertThrows(
                IllegalArgumentException.class,
                () -> AepOpenApi.matchPath(List.of("/items"), "GET", "/items/", AepOpenApi.TrailingSlashMode.STRICT));
        assertEquals(
                "/items",
                AepOpenApi.matchPath(List.of("/items"), "GET", "/items/", AepOpenApi.TrailingSlashMode.EQUIVALENT)
                        .template());
        assertThrows(
                IllegalArgumentException.class,
                () -> AepOpenApi.matchPath(
                        List.of("/items/{id}", "/items/{name}"),
                        "GET",
                        "/items/1",
                        AepOpenApi.TrailingSlashMode.STRICT));
        assertEquals(
                "/a/b/{value}",
                AepOpenApi.matchPath(
                                List.of("/a/{value}/c", "/a/b/{value}"),
                                "GET",
                                "/a/b/c",
                                AepOpenApi.TrailingSlashMode.STRICT)
                        .template());
    }

    @Test
    void resolvesOperationSecurityInheritance() {
        List<Map<String, List<String>>> root = List.of(Map.of(AEP, List.of()));
        List<String> supported = List.of(AEP, KEY);

        assertEquals(
                AepOpenApi.SecurityDisposition.REQUIRED,
                AepOpenApi.resolveSecurity(root, null, supported).disposition(),
                "an operation that omits security inherits the root requirement");
        assertEquals(
                AepOpenApi.SecurityDisposition.PUBLIC,
                AepOpenApi.resolveSecurity(root, List.of(), supported).disposition(),
                "an empty array at the operation replaces the root requirement");
        assertEquals(
                AepOpenApi.SecurityDisposition.PUBLIC,
                AepOpenApi.resolveSecurity(null, null, supported).disposition(),
                "a document with no security anywhere is public");
        assertEquals(
                AepOpenApi.SecurityDisposition.OPTIONAL_ANONYMOUS,
                AepOpenApi.resolveSecurity(root, List.of(Map.of(), Map.of(AEP, List.of())), supported)
                        .disposition(),
                "an empty requirement object permits anonymous access as one alternative");
        assertEquals(
                AepOpenApi.SecurityDisposition.ALTERNATIVES,
                AepOpenApi.resolveSecurity(root, List.of(Map.of(AEP, List.of()), Map.of(KEY, List.of())), supported)
                        .disposition(),
                "several requirement objects are alternatives");
        assertEquals(
                AepOpenApi.SecurityDisposition.ALL_REQUIRED,
                AepOpenApi.resolveSecurity(root, List.of(Map.of(AEP, List.of(), KEY, List.of())), supported)
                        .disposition(),
                "several schemes in one object are compound");
    }

    @Test
    void refusesToReduceAnUnsatisfiableCompoundRequirement() {
        List<Map<String, List<String>>> compound = List.of(Map.of(AEP, List.of(), "mtlsScheme", List.of()));

        AepOpenApi.SecurityResolution resolution = AepOpenApi.resolveSecurity(null, compound, List.of(AEP));

        assertEquals(
                AepOpenApi.SecurityDisposition.FALLBACK_LIVE_CHALLENGE,
                resolution.disposition(),
                "a compound requirement with an unsupported member is unsupported as a whole");
        assertEquals(List.of(), resolution.satisfiable(), "the supported member alone is not an alternative");
        assertEquals("fallback-live-challenge", resolution.disposition().value());
    }

    @Test
    void selectsTheCompleteAlternativeAmongCompoundRequirements() {
        List<Map<String, List<String>>> alternatives =
                List.of(Map.of(AEP, List.of(), "mtlsScheme", List.of()), Map.of(KEY, List.of()));

        AepOpenApi.SecurityResolution resolution = AepOpenApi.resolveSecurity(null, alternatives, List.of(AEP, KEY));

        assertEquals(AepOpenApi.SecurityDisposition.ALTERNATIVES, resolution.disposition());
        assertEquals(List.of(List.of(KEY)), resolution.satisfiable(), "only the complete alternative is selectable");
    }

    @Test
    void rejectsMalformedSecurityInput() {
        List<Map<String, List<String>>> withNull = new java.util.ArrayList<>();
        withNull.add(null);

        assertThrows(IllegalArgumentException.class, () -> AepOpenApi.resolveSecurity(null, withNull, List.of(AEP)));
        assertEquals(
                AepOpenApi.SecurityDisposition.FALLBACK_LIVE_CHALLENGE,
                AepOpenApi.resolveSecurity(null, List.of(Map.of(AEP, List.of())), null)
                        .disposition(),
                "an Agent that supports nothing falls back to a live challenge");
        assertEquals(
                List.of(),
                new AepOpenApi.SecurityResolution(AepOpenApi.SecurityDisposition.PUBLIC, null).satisfiable());
    }
}
