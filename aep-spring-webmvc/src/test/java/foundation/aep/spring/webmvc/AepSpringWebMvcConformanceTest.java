package foundation.aep.spring.webmvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.head;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import foundation.aep.core.Aep;
import foundation.aep.core.AepCommand;
import foundation.aep.core.AgentStatus;
import foundation.aep.core.ClientAssertionClaims;
import foundation.aep.core.InspectDocument;
import foundation.aep.service.AepHttpRequest;
import foundation.aep.service.AepService;
import foundation.aep.service.AepServiceHttpHandler;
import foundation.aep.service.EnrollmentDecision;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.servlet.function.RouterFunctions;
import org.springframework.web.servlet.function.ServerResponse;

/** Checks of the Spring Web MVC functional binding. */
final class AepSpringWebMvcConformanceTest {
    private static final Instant NOW = Instant.parse("2026-09-01T12:00:00Z");
    private static final String AGENT_DID = "did:web:agent.example";
    private static final String ORIGIN = "https://service.example";
    private static final String ENROLL_BODY = "{\"agent_did\":\"did:web:agent.example\"}";

    /** RFC 9110 section 9.3.2: HEAD repeats a GET's headers and carries no content. */
    @Test
    void answersHeadWithoutContent() throws Exception {
        MockMvc client = routed(service("/aep"));

        client.perform(head(Aep.WELL_KNOWN_PATH))
                .andExpect(status().isOk())
                .andExpect(content().string(""))
                .andExpect(header().exists("ETag"))
                .andExpect(header().string("Cache-Control", "public, max-age=300"));
        client.perform(get(Aep.WELL_KNOWN_PATH))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("\"aep_version\"")));
    }

    /** RFC 9110 section 15.4.5: a matching validator revalidates to 304 with no content. */
    @Test
    void revalidatesThroughNotModified() throws Exception {
        AepServiceHttpHandler handler = new AepServiceHttpHandler(service("/aep"));
        MockMvc client =
                MockMvcBuilders.routerFunctions(AepSpringWebMvc.routes(handler)).build();

        client.perform(get(Aep.WELL_KNOWN_PATH).header("If-None-Match", handler.inspectEntityTag()))
                .andExpect(status().isNotModified())
                .andExpect(content().string(""))
                .andExpect(header().string("ETag", handler.inspectEntityTag()));
    }

    /**
     * RequestPredicates.path reads its argument as a PathPattern. An endpoint_base may legally
     * contain an asterisk, which would otherwise have routed AEP commands at unadvertised paths.
     */
    @Test
    void routesOnlyTheExactAdvertisedPath() throws Exception {
        MockMvc client = routed(service("/aep*"));

        client.perform(get("/aep*/status")).andExpect(status().isUnauthorized());
        client.perform(get("/aepXYZ/status")).andExpect(status().isNotFound());
        client.perform(get("/aep/status")).andExpect(status().isNotFound());
    }

    @Test
    void routesEncodedAdvertisedPathsLiterally() throws Exception {
        for (String base : List.of("/aep%20v1", "/aep%3Av1", "/aep%2Fv1")) {
            MockMvc client = routed(service(base));
            client.perform(get(URI.create(base + "/status"))).andExpect(status().isUnauthorized());
            client.perform(get(URI.create(base + "/status/extra"))).andExpect(status().isNotFound());
            client.perform(get("/aep/status")).andExpect(status().isNotFound());
        }
    }

    /** The command path carries its body, media type, and idempotency key through Spring. */
    @Test
    void servesAnEnrollCommand() throws Exception {
        routed(service("/aep"))
                .perform(post("/aep/enroll")
                        .contentType(Aep.MEDIA_TYPE)
                        .header("Authorization", "AEP assertion")
                        .header("Idempotency-Key", "key")
                        .content(ENROLL_BODY))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("\"status\":\"active\"")))
                .andExpect(header().string("Cache-Control", "no-store"));
    }

    /** A protected route reaches the application only once a credential has been accepted. */
    @Test
    void protectsApplicationRoutes() throws Exception {
        AepServiceHttpHandler handler = new AepServiceHttpHandler(service("/aep"));
        enroll(handler);
        MockMvc client = MockMvcBuilders.routerFunctions(RouterFunctions.route()
                        .GET(
                                "/orders",
                                request -> ServerResponse.ok()
                                        .body(String.valueOf(
                                                request.attributes().get(AepSpringWebMvc.PRINCIPAL_ATTRIBUTE))))
                        .filter(AepSpringWebMvc.protect(handler, URI.create(ORIGIN)))
                        .build())
                .build();

        client.perform(get("/orders"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().exists("WWW-Authenticate"));
        client.perform(get("/orders").header("Authorization", "AEP assertion"))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString(AGENT_DID)));
    }

    /** A downstream failure is surfaced rather than swallowed into an empty response. */
    @Test
    void surfacesDownstreamFailuresFromProtectedRoutes() throws Exception {
        AepServiceHttpHandler handler = new AepServiceHttpHandler(service("/aep"));
        enroll(handler);
        MockMvc client = MockMvcBuilders.routerFunctions(RouterFunctions.route()
                        .GET("/orders", request -> {
                            throw new IllegalStateException("downstream");
                        })
                        .filter(AepSpringWebMvc.protect(handler, URI.create(ORIGIN)))
                        .build())
                .build();

        var thrown = Assertions.assertThrows(
                Exception.class,
                () -> client.perform(get("/orders").header("Authorization", "AEP assertion"))
                        .andReturn());

        Assertions.assertTrue(rootCause(thrown) instanceof IllegalStateException);
    }

    @Test
    void refusesUnusableConfiguration() {
        AepServiceHttpHandler handler = new AepServiceHttpHandler(service("/aep"));

        Assertions.assertThrows(NullPointerException.class, () -> AepSpringWebMvc.routes(null));
        Assertions.assertThrows(NullPointerException.class, () -> AepSpringWebMvc.protect(null, URI.create(ORIGIN)));
        Assertions.assertThrows(IllegalArgumentException.class, () -> AepSpringWebMvc.protect(handler, null));
        Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> AepSpringWebMvc.protect(handler, URI.create("https://service.example/base")));
    }

    @Test
    void keepsRequestContextWhileAwaitingAuthentication() throws Exception {
        Gate gate = new Gate();
        AepServiceHttpHandler handler = new AepServiceHttpHandler(gatedService(gate));
        enroll(handler);
        gate.close();
        Thread requestThread = Thread.currentThread();
        MockMvc client = MockMvcBuilders.routerFunctions(RouterFunctions.route()
                        .GET("/orders", request -> {
                            Assertions.assertSame(requestThread, Thread.currentThread());
                            Assertions.assertNotNull(
                                    org.springframework.web.context.request.RequestContextHolder
                                            .getRequestAttributes());
                            var principal = (foundation.aep.service.AuthenticatedPrincipal)
                                    request.attributes().get(AepSpringWebMvc.PRINCIPAL_ATTRIBUTE);
                            return ServerResponse.ok().body(principal.agentDid());
                        })
                        .filter(AepSpringWebMvc.protect(handler, URI.create(ORIGIN)))
                        .build())
                .build();
        CompletableFuture<Void> completion = gate.releaseAfterLookup();
        var result = client.perform(get("/orders").header("Authorization", "AEP assertion"))
                .andExpect(status().isOk())
                .andExpect(content().string(AGENT_DID))
                .andReturn();
        completion.get(5, java.util.concurrent.TimeUnit.SECONDS);
        Assertions.assertFalse(result.getRequest().isAsyncStarted());
    }

    @Test
    void rejectsAfterAwaitingAuthentication() throws Exception {
        Gate gate = new Gate();
        gate.close();
        AepServiceHttpHandler handler = new AepServiceHttpHandler(gatedService(gate));
        MockMvc client = MockMvcBuilders.routerFunctions(RouterFunctions.route()
                        .GET("/orders", request -> {
                            Assertions.fail("An unrecognized Agent must not reach the application.");
                            return ServerResponse.ok().build();
                        })
                        .filter(AepSpringWebMvc.protect(handler, URI.create(ORIGIN)))
                        .build())
                .build();
        CompletableFuture<Void> completion = gate.releaseAfterLookup();
        client.perform(get("/orders").header("Authorization", "AEP assertion"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().exists("WWW-Authenticate"));
        completion.get(5, java.util.concurrent.TimeUnit.SECONDS);
    }

    @Test
    void permitsAsynchronousApplicationResponsesAfterAuthentication() throws Exception {
        Gate gate = new Gate();
        AepServiceHttpHandler handler = new AepServiceHttpHandler(gatedService(gate));
        enroll(handler);
        gate.close();
        CompletableFuture<ServerResponse> application = new CompletableFuture<>();
        MockMvc client = MockMvcBuilders.routerFunctions(RouterFunctions.route()
                        .GET("/orders", request -> {
                            Assertions.assertNotNull(
                                    org.springframework.web.context.request.RequestContextHolder
                                            .getRequestAttributes());
                            return ServerResponse.async(application);
                        })
                        .filter(AepSpringWebMvc.protect(handler, URI.create(ORIGIN)))
                        .build())
                .build();
        CompletableFuture<Void> completion = gate.releaseAfterLookup();
        var initial = client.perform(get("/orders").header("Authorization", "AEP assertion"))
                .andReturn();
        completion.get(5, java.util.concurrent.TimeUnit.SECONDS);
        Assertions.assertTrue(initial.getRequest().isAsyncStarted());
        application.complete(ServerResponse.ok().body("application result"));
        client.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.asyncDispatch(initial))
                .andExpect(status().isOk())
                .andExpect(content().string("application result"));
    }

    @Test
    void surfacesPendingAuthenticationFailuresWithoutInvokingTheApplication() throws Exception {
        Gate gate = new Gate();
        gate.close();
        AepServiceHttpHandler handler = new AepServiceHttpHandler(gatedService(gate));
        MockMvc client = MockMvcBuilders.routerFunctions(RouterFunctions.route()
                        .GET("/orders", request -> {
                            Assertions.fail("Failed authentication must not reach the application.");
                            return ServerResponse.ok().build();
                        })
                        .filter(AepSpringWebMvc.protect(handler, URI.create(ORIGIN)))
                        .build())
                .build();
        IllegalStateException failure = new IllegalStateException("store unavailable");
        CompletableFuture<Void> completion = gate.releaseAfterLookup(failure);
        Exception thrown = Assertions.assertThrows(
                Exception.class, () -> client.perform(get("/orders").header("Authorization", "AEP assertion")));
        completion.get(5, java.util.concurrent.TimeUnit.SECONDS);
        Assertions.assertSame(failure, rootCause(thrown));
    }

    /** Holds the enrollment lookup open so protect() sees an authentication that has not settled. */
    private static final class Gate {
        private volatile CompletableFuture<Void> latch = CompletableFuture.completedFuture(null);
        private CompletableFuture<Void> entered = new CompletableFuture<>();

        void close() {
            latch = new CompletableFuture<>();
            entered = new CompletableFuture<>();
        }

        CompletableFuture<Void> releaseAfterLookup() {
            return releaseAfterLookup(null);
        }

        CompletableFuture<Void> releaseAfterLookup(Throwable failure) {
            return entered.orTimeout(5, java.util.concurrent.TimeUnit.SECONDS)
                    .thenRunAsync(
                            () -> {
                                if (failure == null) latch.complete(null);
                                else latch.completeExceptionally(failure);
                            },
                            CompletableFuture.delayedExecutor(50, java.util.concurrent.TimeUnit.MILLISECONDS));
        }

        CompletableFuture<Void> latch() {
            entered.complete(null);
            return latch;
        }
    }

    private static AepService gatedService(Gate gate) {
        foundation.aep.service.EnrollmentStore delegate = foundation.aep.service.EnrollmentStore.inMemory();
        foundation.aep.service.EnrollmentStore gated = new foundation.aep.service.EnrollmentStore() {
            @Override
            public java.util.concurrent.CompletionStage<java.util.Optional<foundation.aep.service.EnrollmentRecord>>
                    find(String agentDid) {
                return gate.latch().thenCompose(ignored -> delegate.find(agentDid));
            }

            @Override
            public java.util.concurrent.CompletionStage<foundation.aep.service.EnrollmentSelection> findOrCreate(
                    String agentDid,
                    java.util.function.Supplier<
                                    java.util.concurrent.CompletionStage<foundation.aep.service.EnrollmentRecord>>
                            create) {
                return delegate.findOrCreate(agentDid, create);
            }

            @Override
            public java.util.concurrent.CompletionStage<foundation.aep.service.EnrollmentRecord> save(
                    foundation.aep.service.EnrollmentRecord record) {
                return delegate.save(record);
            }
        };
        InspectDocument document = InspectDocument.builder()
                .version(Aep.VERSION)
                .authentication(new InspectDocument.Authentication(List.of(Aep.AUTHENTICATION_METHOD_JWT)))
                .bindings(new InspectDocument.Bindings(List.of("http")))
                .claims(new InspectDocument.Claims(List.of(), List.of(), List.of()))
                .commands(new InspectDocument.Commands(List.of("enroll", "inspect", "status"), List.of(), Map.of()))
                .core(new InspectDocument.Core(Aep.REQUIRED_SIGNING_ALGORITHMS))
                .http(new InspectDocument.Http("/aep", null))
                .identity(new InspectDocument.Identity(List.of("did:web")))
                .service(new InspectDocument.Service("did:web:service.example"))
                .build();
        return AepService.builder(
                        document,
                        (assertion, context) -> CompletableFuture.completedFuture(new ClientAssertionClaims(
                                AGENT_DID,
                                AGENT_DID,
                                context.serviceDid(),
                                context.operation(),
                                NOW.minusSeconds(1).getEpochSecond(),
                                NOW.plusSeconds(60).getEpochSecond(),
                                assertion,
                                context.resource())))
                .clock(Clock.fixed(NOW, ZoneOffset.UTC))
                .enrollmentStore(gated)
                .enrollmentPolicy((request, now) -> CompletableFuture.completedFuture(
                        new EnrollmentDecision(AgentStatus.ACTIVE, false, List.of(), List.of())))
                .build();
    }

    /** A synchronous authentication keeps the downstream handler on the request thread. */
    @Test
    void doesNotForceProtectedRoutesIntoAnAsyncDispatch() throws Exception {
        AepServiceHttpHandler handler = new AepServiceHttpHandler(service("/aep"));
        enroll(handler);
        MockMvc client = MockMvcBuilders.routerFunctions(RouterFunctions.route()
                        .GET("/orders", request -> ServerResponse.ok().body("thread"))
                        .filter(AepSpringWebMvc.protect(handler, URI.create(ORIGIN)))
                        .build())
                .build();

        var result = client.perform(get("/orders").header("Authorization", "AEP assertion"))
                .andExpect(status().isOk())
                .andReturn();

        Assertions.assertFalse(result.getRequest().isAsyncStarted());
    }

    private static Throwable rootCause(Throwable value) {
        Throwable cause = value;
        while (cause.getCause() != null && cause.getCause() != cause) cause = cause.getCause();
        return cause;
    }

    private static MockMvc routed(AepService service) {
        return MockMvcBuilders.routerFunctions(AepSpringWebMvc.routes(new AepServiceHttpHandler(service)))
                .build();
    }

    private static void enroll(AepServiceHttpHandler handler) {
        handler.handle(
                        AepCommand.ENROLL,
                        new AepHttpRequest(
                                "POST",
                                URI.create(ORIGIN + "/aep/enroll"),
                                Map.of(
                                        "Content-Type",
                                        List.of(Aep.MEDIA_TYPE),
                                        "Authorization",
                                        List.of("AEP enrollment"),
                                        "Idempotency-Key",
                                        List.of("enroll-key")),
                                ENROLL_BODY.getBytes(StandardCharsets.UTF_8)))
                .toCompletableFuture()
                .join();
    }

    private static AepService service(String endpointBase) {
        InspectDocument document = InspectDocument.builder()
                .version(Aep.VERSION)
                .authentication(new InspectDocument.Authentication(List.of(Aep.AUTHENTICATION_METHOD_JWT)))
                .bindings(new InspectDocument.Bindings(List.of("http")))
                .claims(new InspectDocument.Claims(List.of(), List.of(), List.of()))
                .commands(new InspectDocument.Commands(List.of("enroll", "inspect", "status"), List.of(), Map.of()))
                .core(new InspectDocument.Core(Aep.REQUIRED_SIGNING_ALGORITHMS))
                .http(new InspectDocument.Http(endpointBase, null))
                .identity(new InspectDocument.Identity(List.of("did:web")))
                .service(new InspectDocument.Service("did:web:service.example"))
                .build();
        return AepService.builder(
                        document,
                        (assertion, context) -> CompletableFuture.completedFuture(new ClientAssertionClaims(
                                AGENT_DID,
                                AGENT_DID,
                                context.serviceDid(),
                                context.operation(),
                                NOW.minusSeconds(1).getEpochSecond(),
                                NOW.plusSeconds(60).getEpochSecond(),
                                assertion,
                                context.resource())))
                .clock(Clock.fixed(NOW, ZoneOffset.UTC))
                .enrollmentPolicy((request, now) -> CompletableFuture.completedFuture(
                        new EnrollmentDecision(AgentStatus.ACTIVE, false, List.of(), List.of())))
                .build();
    }
}
