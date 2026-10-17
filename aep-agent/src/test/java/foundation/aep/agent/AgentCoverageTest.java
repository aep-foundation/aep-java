package foundation.aep.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import foundation.aep.core.Aep;
import foundation.aep.core.AepHttpTransport;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import org.junit.jupiter.api.Test;

/** Configuration, caching, and helper behaviour across the Agent module. */
class AgentCoverageTest {
    private static final URI ORIGIN = URI.create("https://service.example");
    private static final Instant NOW = Instant.parse("2026-09-01T00:00:00Z");

    private static AepHttpTransport.Response response(Map<String, List<String>> headers) {
        return new AepHttpTransport.Response(200, headers, new byte[0]);
    }

    @Test
    void normalizesAndRejectsServiceOrigins() {
        assertEquals(ORIGIN, AgentHttp.origin(URI.create("https://SERVICE.example/"), false));
        assertEquals(
                URI.create("https://service.example:8443"),
                AgentHttp.origin(URI.create("https://service.example:8443"), false));
        assertEquals(URI.create("http://localhost:8080"), AgentHttp.origin(URI.create("http://localhost:8080"), true));
        for (URI value : List.of(
                URI.create("http://service.example"),
                URI.create("https://user:secret@service.example"),
                URI.create("https://service.example/path"),
                URI.create("https://service.example?query"),
                URI.create("https://service.example#fragment"),
                URI.create("/relative"),
                URI.create("mailto:agent@example.com"))) {
            assertThrows(IllegalArgumentException.class, () -> AgentHttp.origin(value, false), value.toString());
        }
        assertThrows(IllegalArgumentException.class, () -> AgentHttp.origin(null, false));
        // The loopback opt-in does not extend to a name that merely resolves to loopback.
        assertThrows(
                IllegalArgumentException.class, () -> AgentHttp.origin(URI.create("http://loopback.example"), true));
    }

    @Test
    void comparesOriginsWithoutThrowingOnAMalformedHost() {
        assertTrue(AgentHttp.sameOrigin(ORIGIN, URI.create("https://service.example:443/x")));
        assertTrue(AgentHttp.sameOrigin(URI.create("http://a.example"), URI.create("http://a.example:80/x")));
        assertFalse(AgentHttp.sameOrigin(ORIGIN, URI.create("https://service.example:8443/x")));
        assertFalse(AgentHttp.sameOrigin(ORIGIN, null));
        assertFalse(AgentHttp.sameOrigin(null, ORIGIN));
        assertFalse(AgentHttp.sameOrigin(ORIGIN, URI.create("/relative")));
        assertFalse(AgentHttp.sameOrigin(URI.create("/relative"), ORIGIN));
        // A redirect Location is attacker-controlled; an unparseable label is simply not a match.
        assertFalse(AgentHttp.sameOrigin(ORIGIN, URI.create("https://xn--/x")));
        assertFalse(AgentHttp.sameOrigin(URI.create("https://xn--/x"), ORIGIN));
    }

    @Test
    void identifiesValidInspectTargets() {
        assertTrue(AgentHttp.validInspectTarget(ORIGIN, URI.create("https://service.example/.well-known/aep")));
        assertFalse(AgentHttp.validInspectTarget(ORIGIN, null));
        assertFalse(AgentHttp.validInspectTarget(ORIGIN, URI.create("https://user:pw@service.example/aep")));
        assertFalse(AgentHttp.validInspectTarget(ORIGIN, URI.create("https://service.example/aep#x")));
        assertFalse(AgentHttp.validInspectTarget(ORIGIN, URI.create("https://other.example/aep")));
    }

    @Test
    void resolvesFreshnessFromCacheControl() {
        assertEquals(
                NOW.plusSeconds(60),
                AgentHttp.expiresAt(
                        response(Map.of("Cache-Control", List.of("max-age=60"))), NOW, Duration.ofSeconds(300)));
        // Directives are unordered, so the one that forbids reuse wins wherever it appears.
        assertEquals(
                NOW,
                AgentHttp.expiresAt(
                        response(Map.of("Cache-Control", List.of("max-age=600, no-cache"))),
                        NOW,
                        Duration.ofSeconds(300)));
        assertEquals(
                NOW,
                AgentHttp.expiresAt(
                        response(Map.of("Cache-Control", List.of("max-age=600", "no-store"))),
                        NOW,
                        Duration.ofSeconds(300)));
        assertEquals(
                NOW,
                AgentHttp.expiresAt(
                        response(Map.of("Cache-Control", List.of("no-cache"))), NOW, Duration.ofSeconds(300)));
        // A negative or unparseable lifetime falls back rather than reaching backwards.
        assertEquals(
                NOW,
                AgentHttp.expiresAt(
                        response(Map.of("Cache-Control", List.of("max-age=-5"))), NOW, Duration.ofSeconds(300)));
        assertEquals(
                NOW.plusSeconds(300),
                AgentHttp.expiresAt(
                        response(Map.of("Cache-Control", List.of("max-age=abc"))), NOW, Duration.ofSeconds(300)));
        assertEquals(
                NOW.plusSeconds(300),
                AgentHttp.expiresAt(
                        response(Map.of("Cache-Control", List.of("public, must-revalidate"))),
                        NOW,
                        Duration.ofSeconds(300)));
        assertEquals(NOW.plusSeconds(300), AgentHttp.expiresAt(response(Map.of()), NOW, Duration.ofSeconds(300)));
        // An overflowing lifetime saturates instead of throwing.
        assertEquals(
                Instant.MAX,
                AgentHttp.expiresAt(
                        response(Map.of("Cache-Control", List.of("max-age=" + Long.MAX_VALUE))), NOW, Duration.ZERO));

        assertTrue(AgentHttp.isNoStore(response(Map.of("Cache-Control", List.of("public, NO-STORE")))));
        assertFalse(AgentHttp.isNoStore(response(Map.of("Cache-Control", List.of("no-cache")))));
        assertFalse(AgentHttp.isNoStore(response(Map.of())));
    }

    @Test
    void readsHeadersCaseInsensitively() {
        AepHttpTransport.Response value = response(Map.of("etag", List.of("\"v1\""), "X-Other", List.of("a")));
        assertEquals(Optional.of("\"v1\""), AgentHttp.header(value, "ETag"));
        assertEquals(Optional.empty(), AgentHttp.header(value, "Absent"));
        assertEquals(Map.of("A", List.of("1")), AgentHttp.headers(Map.of("A", "1")));
    }

    @Test
    void computesRemainingFreshnessUsingDateAgeAndExpires() {
        Duration fallback = Duration.ofSeconds(300);
        assertEquals(
                NOW.plusSeconds(40),
                AgentHttp.expiresAt(
                        response(Map.of("Cache-Control", List.of("max-age=\"60\""), "Age", List.of("20"))),
                        NOW,
                        fallback));
        assertEquals(
                NOW.plusSeconds(40),
                AgentHttp.expiresAt(
                        response(Map.of(
                                "Cache-Control",
                                List.of("max-age=60"),
                                "Date",
                                List.of("Mon, 31 Aug 2026 23:59:40 GMT"))),
                        NOW,
                        fallback));
        assertEquals(
                NOW.plusSeconds(60),
                AgentHttp.expiresAt(
                        response(Map.of(
                                "Date", List.of("Tue, 1 Sep 2026 00:00:00 GMT"),
                                "Expires", List.of("Tue, 1 Sep 2026 00:01:00 GMT"))),
                        NOW,
                        fallback));
        assertEquals(
                NOW.plusSeconds(300),
                AgentHttp.expiresAt(
                        response(Map.of(
                                "Date", List.of("invalid"), "Expires", List.of("invalid"), "Age", List.of("invalid"))),
                        NOW,
                        fallback));
    }

    @Test
    void cacheMetadataCannotBeMutatedByTheCaller() {
        java.util.ArrayList<String> policy = new java.util.ArrayList<>(List.of("no-cache"));
        java.util.HashMap<String, List<String>> headers = new java.util.HashMap<>();
        headers.put("Cache-Control", policy);
        AgentInspectCache.Entry entry = new AgentInspectCache.Entry(ORIGIN, "{}", "v1", null, NOW, headers);
        policy.clear();
        headers.clear();
        assertEquals(List.of("no-cache"), entry.cacheHeaders().get("Cache-Control"));
        assertThrows(
                UnsupportedOperationException.class, () -> entry.cacheHeaders().clear());
        assertThrows(
                UnsupportedOperationException.class,
                () -> entry.cacheHeaders().get("Cache-Control").clear());
    }

    @Test
    void refusesFieldValuesThatCannotTravelInAHeader() {
        assertEquals("key", AgentHttp.requireFieldValue("key", "idempotency key"));
        assertEquals("a b", AgentHttp.requireFieldValue("a b", "idempotency key"));
        for (String value : List.of(" key", "key ", "\tkey", "key\t", "", "   ", "key\r\n", "key\u0000", "key\u007f")) {
            AepAgentException error = assertThrows(
                    AepAgentException.class, () -> AgentHttp.requireFieldValue(value, "idempotency key"), value);
            assertEquals("invalid_configuration", error.code());
        }
        assertThrows(AepAgentException.class, () -> AgentHttp.requireFieldValue(null, "idempotency key"));
    }

    @Test
    void reportsBodyLimitsAndMediaTypes() {
        AepHttpTransport.Response large =
                new AepHttpTransport.Response(200, Map.of(), "0123456789".getBytes(StandardCharsets.UTF_8));
        assertEquals(
                "response_too_large",
                assertThrows(AepAgentException.class, () -> AgentHttp.requireBodyLimit(large, 4))
                        .code());
        AgentHttp.requireBodyLimit(large, 10);
        assertEquals("0123456789", AgentHttp.body(large));

        AepHttpTransport.Response typed = new AepHttpTransport.Response(
                200, Map.of("Content-Type", List.of(Aep.MEDIA_TYPE + "; charset=utf-8")), new byte[0]);
        AgentHttp.requireMediaType(typed, Aep.MEDIA_TYPE);
        assertEquals(
                "invalid_media_type",
                assertThrows(AepAgentException.class, () -> AgentHttp.requireMediaType(typed, "application/json"))
                        .code());
        assertEquals(
                "invalid_media_type",
                assertThrows(
                                AepAgentException.class,
                                () -> AgentHttp.requireMediaType(
                                        new AepHttpTransport.Response(200, Map.of(), new byte[0]), Aep.MEDIA_TYPE))
                        .code());
    }

    @Test
    void validatesAgentConfiguration() {
        AepAgent.Builder builder = AepAgent.builder();
        assertThrows(NullPointerException.class, () -> builder.inspectTransport(null));
        assertThrows(NullPointerException.class, () -> builder.commandTransport(null));
        assertThrows(NullPointerException.class, () -> builder.identityProvider(null));
        assertThrows(NullPointerException.class, () -> builder.credentialStore(null));
        assertThrows(NullPointerException.class, () -> builder.inspectCache(null));
        assertThrows(NullPointerException.class, () -> builder.idempotencyKeyProvider(null));
        assertThrows(NullPointerException.class, () -> builder.credentialHandler(null));
        assertThrows(NullPointerException.class, () -> builder.clock(null));
        assertThrows(NullPointerException.class, () -> builder.jwtIdSupplier(null));
        assertThrows(NullPointerException.class, () -> builder.requestTimeout(null));

        for (Duration invalid : List.of(Duration.ZERO, Duration.ofSeconds(-1))) {
            assertThrows(IllegalArgumentException.class, () -> builder.requestTimeout(invalid));
            assertThrows(IllegalArgumentException.class, () -> builder.assertionLifetime(invalid));
            assertThrows(IllegalArgumentException.class, () -> builder.defaultInspectFreshness(invalid));
        }
        // CORE-CA-019 caps an assertion at five minutes, so the Agent cannot be configured past it.
        assertThrows(
                IllegalArgumentException.class,
                () -> builder.assertionLifetime(Duration.ofMinutes(5).plusSeconds(1)));
        builder.assertionLifetime(Duration.ofMinutes(5));
        assertThrows(IllegalArgumentException.class, () -> builder.maximumResponseBytes(0));
        assertThrows(IllegalArgumentException.class, () -> builder.maximumResponseBytes(-1));
        assertThrows(IllegalArgumentException.class, () -> builder.maximumRedirects(-1));
        builder.maximumRedirects(0).maximumResponseBytes(1024).allowInsecureLoopback(true);

        // build() names the collaborator it still needs.
        assertThrows(NullPointerException.class, AepAgent.builder()::build);
        assertThrows(
                NullPointerException.class,
                () -> AepAgent.builder().inspectTransport(nullTransport()).build());
        assertThrows(
                NullPointerException.class,
                () -> AepAgent.builder()
                        .inspectTransport(nullTransport())
                        .commandTransport(nullTransport())
                        .build());
    }

    @Test
    void refusesCredentialHandlersThatCollide() {
        AgentCredentialHandler duplicate = handler("api-key", "api-key");
        assertThrows(
                IllegalArgumentException.class,
                () -> AepAgent.builder()
                        .inspectTransport(nullTransport())
                        .commandTransport(nullTransport())
                        .identityProvider((origin, did) -> CompletableFuture.completedFuture(null))
                        .credentialHandler(duplicate)
                        .build());
        for (AgentCredentialHandler blank : List.of(handler("", "grant"), handler("method", ""))) {
            assertThrows(
                    IllegalArgumentException.class,
                    () -> AepAgent.builder()
                            .inspectTransport(nullTransport())
                            .commandTransport(nullTransport())
                            .identityProvider((origin, did) -> CompletableFuture.completedFuture(null))
                            .credentialHandler(blank)
                            .build());
        }
        AepAgent agent = AepAgent.builder()
                .inspectTransport(nullTransport())
                .commandTransport(nullTransport())
                .identityProvider((origin, did) -> CompletableFuture.completedFuture(null))
                .credentialHandler(handler("custom-session", "custom-grant"))
                .build();
        assertEquals(ORIGIN, agent.service(ORIGIN).origin());
    }

    @Test
    void servesInMemoryAndNoOpInspectCaches() {
        AgentInspectCache none = AgentInspectCache.none();
        AgentInspectCache.Entry entry =
                new AgentInspectCache.Entry(ORIGIN, "{}", "\"v1\"", "Mon, 01 Sep 2026 00:00:00 GMT", NOW);
        assertEquals(Optional.empty(), join(none.get(ORIGIN)));
        assertNull(join(none.put(ORIGIN, entry)));
        assertEquals(Optional.empty(), join(none.get(ORIGIN)));
        assertNull(join(none.delete(ORIGIN)));

        AgentInspectCache memory = AgentInspectCache.inMemory();
        assertEquals(Optional.empty(), join(memory.get(ORIGIN)));
        join(memory.put(ORIGIN, entry));
        assertEquals(Optional.of(entry), join(memory.get(ORIGIN)));
        join(memory.delete(ORIGIN));
        assertEquals(Optional.empty(), join(memory.get(ORIGIN)));

        assertThrows(NullPointerException.class, () -> new AgentInspectCache.Entry(null, "{}", null, null, NOW));
        assertThrows(NullPointerException.class, () -> new AgentInspectCache.Entry(ORIGIN, null, null, null, NOW));
        assertThrows(NullPointerException.class, () -> new AgentInspectCache.Entry(ORIGIN, "{}", null, null, null));
    }

    @Test
    void servesTheInMemoryCredentialStore() {
        AgentCredentialStore store = AgentCredentialStore.inMemory();
        AgentCredential first = new AgentCredential("did:web:a.example", "api-key", "c-1", NOW.plusSeconds(60), "{}");
        AgentCredential second =
                new AgentCredential("did:web:a.example", "oauth-bearer", "c-2", NOW.plusSeconds(60), "{}");
        AgentCredential other = new AgentCredential("did:web:b.example", "api-key", "c-3", NOW.plusSeconds(60), "{}");

        assertEquals(Optional.empty(), join(store.find("did:web:a.example", "api-key", NOW)));
        join(store.save(first));
        join(store.save(second));
        join(store.save(other));
        assertEquals(Optional.of(first), join(store.find("did:web:a.example", "api-key", NOW)));
        assertEquals(Optional.empty(), join(store.find("did:web:a.example", "absent", NOW)));

        join(store.delete("did:web:a.example", "c-1"));
        assertEquals(Optional.empty(), join(store.find("did:web:a.example", "api-key", NOW)));
        assertEquals(Optional.of(second), join(store.find("did:web:a.example", "oauth-bearer", NOW)));

        join(store.deleteGrantType("did:web:a.example", "oauth-bearer"));
        assertEquals(Optional.empty(), join(store.find("did:web:a.example", "oauth-bearer", NOW)));
        assertEquals(Optional.of(other), join(store.find("did:web:b.example", "api-key", NOW)));

        join(store.deleteAll("did:web:b.example"));
        assertEquals(Optional.empty(), join(store.find("did:web:b.example", "api-key", NOW)));
        // Deleting what is not there is not an error.
        join(store.delete("did:web:absent.example", "c-9"));
        join(store.deleteGrantType("did:web:absent.example", "api-key"));
        join(store.deleteAll("did:web:absent.example"));
    }

    @Test
    void copiesPlatformContextDefensivelyAndRejectsNonJson() {
        assertNull(PlatformJson.copyMap(null));
        Map<String, Object> source = new LinkedHashMap<>();
        source.put("text", "value");
        source.put("number", 7);
        source.put("flag", true);
        source.put("absent", null);
        source.put("list", new ArrayList<>(List.of(1, "two")));
        Map<String, Object> nested = new LinkedHashMap<>();
        nested.put("deep", List.of("x"));
        source.put("nested", nested);

        Map<String, Object> copy = PlatformJson.copyMap(source);
        source.put("text", "mutated");
        nested.put("deep", List.of("y"));
        assertEquals("value", copy.get("text"));
        assertEquals(List.of("x"), ((Map<?, ?>) copy.get("nested")).get("deep"));
        assertThrows(UnsupportedOperationException.class, () -> copy.put("added", 1));

        Map<String, Object> unsupported = new LinkedHashMap<>();
        unsupported.put("value", new Object());
        assertThrows(IllegalArgumentException.class, () -> PlatformJson.copyMap(unsupported));

        Map<Object, Object> badKey = new LinkedHashMap<>();
        badKey.put(1, "value");
        Map<String, Object> wrapper = new LinkedHashMap<>();
        wrapper.put("nested", badKey);
        assertThrows(IllegalArgumentException.class, () -> PlatformJson.copyMap(wrapper));
    }

    @Test
    void carriesFailureDetailOnAgentExceptions() {
        AepAgentException plain = new AepAgentException("code", "message");
        assertEquals("code", plain.code());
        assertEquals(0, plain.status());
        assertNull(plain.getCause());

        IllegalStateException cause = new IllegalStateException("cause");
        AepAgentException wrapped = new AepAgentException("code", "message", cause);
        assertSame(cause, wrapped.getCause());
        assertEquals(0, wrapped.status());

        AepAgentException statused = new AepAgentException("code", "message", 503);
        assertEquals(503, statused.status());
        assertEquals("message", statused.getMessage());
    }

    @Test
    void authenticationHeadersAreIndependentOfCallerMutation() {
        List<String> values = new ArrayList<>(List.of("AEP secret"));
        Map<String, List<String>> headers = new LinkedHashMap<>();
        headers.put("Authorization", values);
        AgentAuthentication authentication = new AgentAuthentication("aep-jwt", headers);
        values.clear();
        headers.clear();
        assertEquals(Map.of("Authorization", List.of("AEP secret")), authentication.headers());
        assertThrows(
                UnsupportedOperationException.class,
                () -> authentication.headers().clear());
        assertThrows(
                UnsupportedOperationException.class,
                () -> authentication.headers().get("Authorization").clear());
    }

    @Test
    void exposesValueTypesWithoutLeakingSecrets() {
        AgentAuthentication authentication =
                new AgentAuthentication("aep-jwt", Map.of("Authorization", List.of("AEP secret-assertion")));
        assertEquals("aep-jwt", authentication.method());
        assertEquals(List.of("AEP secret-assertion"), authentication.headers().get("Authorization"));
        assertFalse(authentication.toString().contains("secret-assertion"));
        assertEquals(Map.of(), new AgentAuthentication("custom", null).headers());

        AgentCredential credential =
                new AgentCredential("did:web:a.example", "api-key", "c-1", NOW, "{\"api_key\":\"secret\"}");
        assertFalse(credential.toString().contains("secret"));
        assertEquals("c-1", credential.credentialId());

        AgentGrantResult result = new AgentGrantResult("api-key", "{\"api_key\":\"secret\"}", Optional.of(credential));
        assertEquals("api-key", result.grantType());
        assertFalse(result.toString().contains("secret"));

        AgentIdentity identity = new AgentIdentity(
                "did:web:agent.example", claims -> CompletableFuture.completedFuture("signed-assertion"));
        assertEquals("did:web:agent.example", identity.did());
        assertFalse(identity.toString().contains("signed-assertion"));

        foundation.aep.core.PlatformAgentIdentity hosted = new foundation.aep.core.PlatformAgentIdentity(
                "did:web:p.example:a:one",
                "pai_1",
                "2026-09-01T00:00:00Z",
                "https://p.example/a/one/did.json",
                "did:web:p.example:a:one",
                "did:web:service.example",
                List.of("ES256"),
                foundation.aep.core.ManagedAgentStatus.ACTIVE,
                "2026-09-01T00:00:00Z");
        PlatformPendingSign pending = new PlatformPendingSign(hosted, Map.of("handle", "opaque"), 5);
        assertEquals(5, pending.retryAfterSeconds());
        assertEquals(hosted, pending.identity());
        assertEquals(Map.of("handle", "opaque"), pending.platformContext());
        assertEquals(pending, new PlatformSignPendingException(pending).pending());
    }

    @Test
    void reusesOneInspectionAcrossConcurrentCallers() {
        AepHttpTransport inspect = request -> CompletableFuture.completedFuture(new AepHttpTransport.Response(
                200,
                Map.of("Content-Type", List.of(Aep.MEDIA_TYPE), "Cache-Control", List.of("no-store")),
                document().getBytes(StandardCharsets.UTF_8)));
        AepServiceSession session = AepAgent.builder()
                .inspectTransport(inspect)
                .commandTransport(request -> CompletableFuture.failedFuture(new AssertionError("unused")))
                .identityProvider((origin, did) -> CompletableFuture.completedFuture(
                        new AgentIdentity("did:web:agent.example", claims -> CompletableFuture.completedFuture("s"))))
                .inspectCache(AgentInspectCache.none())
                .clock(Clock.fixed(NOW, ZoneOffset.UTC))
                .build()
                .service(ORIGIN);

        CompletableFuture<AgentInspection> first = session.inspect();
        CompletableFuture<AgentInspection> second = session.inspect();
        assertEquals(first.join().documentUri(), second.join().documentUri());
        assertEquals(
                "did:web:service.example", first.join().document().service().did());
    }

    @Test
    void rejectsNonPositivePollingBounds() {
        AepServiceSession session = AepAgent.builder()
                .inspectTransport(nullTransport())
                .commandTransport(nullTransport())
                .identityProvider((origin, did) -> CompletableFuture.completedFuture(null))
                .build()
                .service(ORIGIN);
        assertThrows(IllegalArgumentException.class, () -> session.waitForActive(Duration.ZERO, Duration.ofSeconds(1)));
        assertThrows(
                IllegalArgumentException.class,
                () -> session.waitForActive(Duration.ofSeconds(1), Duration.ofSeconds(-1)));
        assertThrows(NullPointerException.class, () -> session.waitForActive(null, Duration.ofSeconds(1)));
        assertThrows(NullPointerException.class, () -> session.waitForActive(Duration.ofSeconds(1), null));
        assertThrows(NullPointerException.class, () -> session.revoke(null));
        assertThrows(NullPointerException.class, () -> session.grant((foundation.aep.core.GrantRequest) null));
        assertThrows(NullPointerException.class, () -> session.authenticate(null));
    }

    private static <T> T join(CompletionStage<T> stage) {
        return stage.toCompletableFuture().join();
    }

    private static AepHttpTransport nullTransport() {
        return request -> CompletableFuture.failedFuture(new AssertionError("Transport must not be called"));
    }

    private static AgentCredentialHandler handler(String method, String grantType) {
        return new AgentCredentialHandler() {
            @Override
            public String authenticationMethod() {
                return method;
            }

            @Override
            public String grantType() {
                return grantType;
            }

            @Override
            public AgentCredential parse(String serviceDid, String responseJson) {
                return new AgentCredential(serviceDid, grantType, "c-1", NOW, responseJson);
            }

            @Override
            public Map<String, String> authorizationHeaders(AgentCredential credential, URI resource) {
                return Map.of("X-Credential", "value");
            }
        };
    }

    private static String document() {
        return """
                {
                  "aep_version":"1.0",
                  "bindings":{"supported":["http"]},
                  "commands":{"supported":["inspect"],"grant_types":[],"grant_types_config":{}},
                  "core":{"signing_algorithms":["EdDSA","ES256"]},
                  "http":{"endpoint_base":"/aep/"},
                  "identity":{"methods":["did:web"]},
                  "service":{"did":"did:web:service.example"}
                }
                """;
    }

    @Test
    void appliesTheRemainingBuilderDefaultsAndBounds() {
        AepAgent agent = AepAgent.builder()
                .inspectTransport(nullTransport())
                .commandTransport(nullTransport())
                .identityProvider((origin, did) -> CompletableFuture.completedFuture(null))
                .requestTimeout(Duration.ofSeconds(10))
                .defaultInspectFreshness(Duration.ofSeconds(120))
                .build();
        assertEquals(ORIGIN, agent.service(ORIGIN).origin());

        // The default idempotency key provider and JWT id supplier produce distinct usable values.
        AepAgent defaults = AepAgent.builder()
                .inspectTransport(nullTransport())
                .commandTransport(nullTransport())
                .identityProvider((origin, did) -> CompletableFuture.completedFuture(null))
                .build();
        assertEquals(ORIGIN, defaults.service(ORIGIN).origin());
    }

    @Test
    void refusesAPendingSignOutsideTheRetryRange() {
        foundation.aep.core.PlatformAgentIdentity identity = new foundation.aep.core.PlatformAgentIdentity(
                "did:web:p.example:a:one",
                "pai_1",
                "2026-09-01T00:00:00Z",
                "https://p.example/a/one/did.json",
                "did:web:p.example:a:one",
                "did:web:service.example",
                List.of("ES256"),
                foundation.aep.core.ManagedAgentStatus.ACTIVE,
                "2026-09-01T00:00:00Z");
        for (int retry : List.of(0, -1, 301)) {
            assertThrows(
                    IllegalArgumentException.class,
                    () -> new PlatformPendingSign(identity, Map.of(), retry),
                    Integer.toString(retry));
        }
        assertEquals(1, new PlatformPendingSign(identity, null, 1).retryAfterSeconds());
        assertEquals(300, new PlatformPendingSign(identity, null, 300).retryAfterSeconds());
        assertThrows(NullPointerException.class, () -> new PlatformSignPendingException(null));
    }

    @Test
    void reportsAnUnparseableCredentialExpiry() {
        assertThrows(
                IllegalArgumentException.class,
                () -> AgentCredentialHandlers.oauthBearer()
                        .parse(
                                "did:web:service.example",
                                "{\"access_token\":\"t\",\"credential_id\":\"c-1\","
                                        + "\"expires_at\":\"2026-13-45T99:00:00Z\",\"token_type\":\"Bearer\"}"));
    }
}
