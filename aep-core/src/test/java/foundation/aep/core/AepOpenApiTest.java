package foundation.aep.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.net.URI;
import java.util.List;
import org.junit.jupiter.api.Test;

final class AepOpenApiTest {
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
}
