package foundation.aep.examples;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import foundation.aep.agent.AepAgent;
import foundation.aep.agent.AepAgentException;
import foundation.aep.agent.AgentAuthentication;
import foundation.aep.agent.PlatformIdentityProvider;
import foundation.aep.core.Aep;
import foundation.aep.core.AepJson;
import foundation.aep.core.ClaimValues;
import foundation.aep.core.ClientAssertionClaims;
import foundation.aep.core.ClientAssertions;
import foundation.aep.core.DidWeb;
import foundation.aep.core.GrantResponses;
import foundation.aep.core.InspectDocument;
import foundation.aep.core.ManagedAgentStatus;
import foundation.aep.core.PlatformDiscoveryDocument;
import foundation.aep.core.PlatformLifecycleRequest;
import foundation.aep.core.PlatformProvisionRequest;
import foundation.aep.core.PlatformSignRequest;
import foundation.aep.core.RevokeRequest;
import foundation.aep.httpserver.AepHttpServer;
import foundation.aep.platform.AepPlatform;
import foundation.aep.platform.PlatformDidVerificationMethod;
import foundation.aep.platform.PlatformIdentityListQuery;
import foundation.aep.platform.PlatformIdentityRecord;
import foundation.aep.platform.PlatformKeyStore;
import foundation.aep.platform.PlatformRequestContext;
import foundation.aep.platform.PlatformResponse;
import foundation.aep.service.AepService;
import foundation.aep.service.AepServiceHttpHandler;
import foundation.aep.service.ClientAssertionVerifier;
import foundation.aep.service.ServiceCredentialStore;
import foundation.aep.service.StoredCredentialGrantTypes;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Executors;

public final class NodeInteroperability {
    private static final String API_KEY_HEADER = "X-API-Key";
    private static final String COMMAND_AGENT = "agent";
    private static final String COMMAND_SERVER = "server";
    private static final String HTTP_GET = "GET";
    private static final String HTTP_POST = "POST";
    private static final int HTTP_OK = 200;
    private static final String PLATFORM_AUTHORIZATION = "Bearer demo-agent";
    private static final String PLATFORM_IDENTITIES = "/platform/agent-identities";
    private static final int MAXIMUM_BODY_BYTES = 65_536;
    private static final int SERVER_THREADS = 4;
    private static final HttpClient HTTP_CLIENT = HttpClient.newHttpClient();

    private NodeInteroperability() {}

    public static void main(String[] arguments) throws Exception {
        if (arguments.length == 0) throw new IllegalArgumentException("Expected agent or server.");
        if (COMMAND_AGENT.equals(arguments[0])) {
            runAgent(arguments);
            return;
        }
        if (COMMAND_SERVER.equals(arguments[0])) {
            runServer(arguments);
            return;
        }
        throw new IllegalArgumentException("Unknown interoperability command: " + arguments[0]);
    }

    private static void runAgent(String... arguments) throws IOException, InterruptedException {
        URI platformOrigin = URI.create(argument(arguments, "--platform-url"));
        URI serviceOrigin = URI.create(argument(arguments, "--service-url"));
        JdkAepTransport transport = new JdkAepTransport();
        PlatformIdentityProvider identities = PlatformIdentityProvider.builder(platformOrigin)
                .transport(transport)
                .authorization(PLATFORM_AUTHORIZATION)
                .allowInsecureLoopback(true)
                .build();
        AepAgent agent = AepAgent.builder()
                .inspectTransport(transport)
                .commandTransport(transport)
                .identityProvider(identities)
                .allowInsecureLoopback(true)
                .build();
        var session = agent.service(serviceOrigin);
        var inspection = session.inspect().join();
        var enrollment = session.enroll(ClaimValues.builder().build()).join();
        var grant = session.grant(Aep.GRANT_TYPE_API_KEY, List.of("read:resource", "write:profile"))
                .join();
        String credentialId = grant.credential().orElseThrow().credentialId();
        URI resource = serviceOrigin.resolve("/api/resource");
        AgentAuthentication authentication = session.authenticate(resource).join();
        HttpResponse<String> protectedResponse = send(transport, resource, HTTP_GET, null, authentication);
        session.revoke(RevokeRequest.credential(Aep.GRANT_TYPE_API_KEY, credentialId))
                .join();
        boolean revoked = false;
        try {
            session.authenticate(resource).join();
        } catch (CompletionException exception) {
            if (exception.getCause() instanceof AepAgentException agentException
                    && "authentication_unavailable".equals(agentException.code())) {
                revoked = true;
            } else {
                throw exception;
            }
        }
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("agent", "java");
        result.put("credential_mode", grant.grantType());
        result.put("enrollment", enrollment.status().value());
        result.put("platform", "node");
        result.put("protected_resource_status", protectedResponse.statusCode());
        result.put("revoked", revoked);
        result.put("service", "node");
        result.put("service_did", inspection.document().service().did());
        System.out.println(AepJson.write(result)); // NOPMD - Interoperability process output.
    }

    private static void runServer(String... arguments) throws IOException, InterruptedException {
        String listen = argument(arguments, "--listen");
        int separator = listen.lastIndexOf(':');
        String host = listen.substring(0, separator);
        int port = Integer.parseInt(listen.substring(separator + 1));
        String encodedHost = listen.replace(":", "%3A");
        String serviceDid = "did:web:" + encodedHost + ":services:store";
        String platformServiceDid = System.getenv("AEP_INTEROP_SERVICE_DID");
        if (platformServiceDid == null || platformServiceDid.isBlank()) platformServiceDid = serviceDid;
        InteroperabilityKeyStore keys = new InteroperabilityKeyStore();
        AepPlatform platform = platform(listen, platformServiceDid, keys);
        AepServiceHttpHandler service = service(serviceDid);
        HttpServer server = HttpServer.create(new InetSocketAddress(host, port), 0);
        server.setExecutor(Executors.newFixedThreadPool(SERVER_THREADS));
        AepHttpServer.register(server, service);
        URI origin = URI.create("http://" + listen);
        server.createContext(
                "/api/resource",
                AepHttpServer.protect(
                        service,
                        origin,
                        exchange -> json(exchange, 200, "application/json", Map.of("available", true))));
        server.createContext(
                "/api/profile",
                AepHttpServer.protect(
                        service, origin, exchange -> json(exchange, 200, "application/json", Map.of("updated", true))));
        server.createContext(
                "/services/store/did.json",
                exchange -> json(
                        exchange,
                        200,
                        Aep.DID_MEDIA_TYPE,
                        Map.of("@context", List.of("https://www.w3.org/ns/did/v1"), "id", serviceDid)));
        server.createContext("/.well-known/aep-platform", exchange -> write(exchange, platform.discovery()));
        server.createContext(PLATFORM_IDENTITIES, exchange -> platform(exchange, platform));
        server.createContext("/agents", exchange -> didDocument(exchange, platform));
        server.createContext("/health", exchange -> json(exchange, 200, "application/json", Map.of("ok", true)));
        server.start();
        new java.util.concurrent.CountDownLatch(1).await();
    }

    private static AepServiceHttpHandler service(String serviceDid) {
        InspectDocument.GrantTypeConfig apiKeyConfig = new InspectDocument.GrantTypeConfig(
                null,
                "3600",
                List.of(API_KEY_HEADER),
                null,
                List.of("read:resource", "write:profile"),
                "true",
                null,
                null);
        InspectDocument document = InspectDocument.builder()
                .version(Aep.VERSION)
                .authentication(new InspectDocument.Authentication(List.of(Aep.GRANT_TYPE_API_KEY)))
                .bindings(new InspectDocument.Bindings(List.of("http")))
                .claims(new InspectDocument.Claims(List.of(), List.of(), List.of()))
                .commands(new InspectDocument.Commands(
                        List.of("enroll", "grant", "inspect", "revoke", "status"),
                        List.of(Aep.GRANT_TYPE_API_KEY),
                        Map.of(Aep.GRANT_TYPE_API_KEY, apiKeyConfig)))
                .core(new InspectDocument.Core(Aep.REQUIRED_SIGNING_ALGORITHMS))
                .http(new InspectDocument.Http("/aep/", null))
                .identity(new InspectDocument.Identity(List.of(Aep.IDENTITY_METHOD_DID_WEB)))
                .service(new InspectDocument.Service(serviceDid))
                .build();
        ServiceCredentialStore credentials = ServiceCredentialStore.inMemory();
        var apiKey = StoredCredentialGrantTypes.apiKey(
                apiKeyConfig,
                (request, context) -> CompletableFuture.completedFuture(new GrantResponses.ApiKey(
                        UUID.randomUUID().toString(),
                        UUID.randomUUID().toString(),
                        context.now().plus(1, ChronoUnit.HOURS).toString(),
                        API_KEY_HEADER,
                        request.requestedScopes())),
                credentials);
        AepService protocol = AepService.builder(
                        document,
                        ClientAssertionVerifier.withKeyResolver(
                                (assertion, claims, context) -> resolveAgentKey(assertion, claims.issuer())))
                .allowInsecureLoopback(true)
                .storedCredentialGrantType(apiKey)
                .build();
        return new AepServiceHttpHandler(protocol);
    }

    private static CompletionStage<JWK> resolveAgentKey(String assertion, String agentDid) {
        URI documentUri;
        try {
            documentUri = DidWeb.documentUri(agentDid, true);
        } catch (IllegalArgumentException exception) {
            return CompletableFuture.failedFuture(exception);
        }
        HttpRequest request = HttpRequest.newBuilder(documentUri)
                .header("Accept", Aep.DID_MEDIA_TYPE)
                .GET()
                .build();
        return HTTP_CLIENT
                .sendAsync(request, HttpResponse.BodyHandlers.ofString())
                .thenApply(response -> {
                    if (response.statusCode() != HTTP_OK) {
                        throw new IllegalArgumentException(
                                "Agent DID document returned HTTP " + response.statusCode() + ".");
                    }
                    try {
                        Map<String, Object> document = JSONObjectUtils.parse(response.body());
                        if (!agentDid.equals(document.get("id"))) {
                            throw new IllegalArgumentException("Agent DID document identifier does not match.");
                        }
                        String keyId = SignedJWT.parse(assertion).getHeader().getKeyID();
                        if (keyId == null || keyId.isBlank()) {
                            throw new IllegalArgumentException(
                                    "Agent assertion does not identify a verification method.");
                        }
                        int fragment = keyId.indexOf('#');
                        String keyDid = fragment < 0 ? keyId : keyId.substring(0, fragment);
                        if (!agentDid.equals(keyDid)) {
                            throw new IllegalArgumentException(
                                    "Agent verification method does not identify the assertion issuer.");
                        }
                        Map<String, Object>[] methods =
                                JSONObjectUtils.getJSONObjectArray(document, "verificationMethod");
                        if (methods == null) {
                            throw new IllegalArgumentException("Agent DID document has no verification methods.");
                        }
                        for (Map<String, Object> method : methods) {
                            if (keyId.equals(method.get("id"))) {
                                return JWK.parse(JSONObjectUtils.getJSONObject(method, "publicKeyJwk"));
                            }
                        }
                        throw new IllegalArgumentException("Agent verification method was not found.");
                    } catch (java.text.ParseException exception) {
                        throw new IllegalArgumentException("Agent DID document is invalid.", exception);
                    }
                });
    }

    private static AepPlatform platform(String host, String serviceDid, InteroperabilityKeyStore keys) {
        PlatformDiscoveryDocument discovery = new PlatformDiscoveryDocument(
                Aep.VERSION,
                new PlatformDiscoveryDocument.Endpoints(
                        null,
                        PLATFORM_IDENTITIES + "/{agent_identity_id}",
                        PLATFORM_IDENTITIES,
                        PLATFORM_IDENTITIES,
                        PLATFORM_IDENTITIES + "/{agent_identity_id}/sign"),
                new PlatformDiscoveryDocument.Http("/platform/"),
                new PlatformDiscoveryDocument.Identity(
                        List.of(Aep.IDENTITY_METHOD_DID_WEB), "https://" + host + "/agents/{agent_did_id}/did.json"),
                new PlatformDiscoveryDocument.Platform("did:web:" + host.replace(":", "%3A"), false, "Java Platform"),
                new PlatformDiscoveryDocument.Signing(List.of("ES256"), "300"));
        return AepPlatform.builder(
                        discovery,
                        host,
                        (request, context) -> CompletableFuture.completedFuture(
                                context != null && "demo-agent".equals(context.principal())),
                        keys,
                        (candidate, context) -> CompletableFuture.completedFuture(serviceDid.equals(candidate)))
                .build();
    }

    private static void platform(HttpExchange exchange, AepPlatform platform) throws IOException {
        String path = exchange.getRequestURI().getRawPath();
        String root = PLATFORM_IDENTITIES;
        PlatformRequestContext context = platformContext(exchange);
        if (root.equals(path)) {
            if (HTTP_GET.equals(exchange.getRequestMethod())) {
                write(
                        exchange,
                        platform.list(listQuery(exchange.getRequestURI().getRawQuery()), context)
                                .toCompletableFuture()
                                .join());
                return;
            }
            if (HTTP_POST.equals(exchange.getRequestMethod())) {
                PlatformProvisionRequest request = AepJson.parsePlatformProvisionRequest(body(exchange));
                write(
                        exchange,
                        platform.provision(request, context)
                                .toCompletableFuture()
                                .join());
                return;
            }
        }
        String remainder = path.startsWith(root + "/") ? path.substring(root.length() + 1) : "";
        if (remainder.endsWith("/sign") && HTTP_POST.equals(exchange.getRequestMethod())) {
            String identity = decode(remainder.substring(0, remainder.length() - "/sign".length()));
            PlatformSignRequest request = AepJson.parsePlatformSignRequest(body(exchange));
            write(
                    exchange,
                    platform.sign(identity, request, context)
                            .toCompletableFuture()
                            .join());
            return;
        }
        if (!remainder.isEmpty() && HTTP_GET.equals(exchange.getRequestMethod())) {
            write(
                    exchange,
                    platform.getIdentity(decode(remainder), context)
                            .toCompletableFuture()
                            .join());
            return;
        }
        if (!remainder.isEmpty() && "PATCH".equals(exchange.getRequestMethod())) {
            PlatformLifecycleRequest request = AepJson.parsePlatformLifecycleRequest(body(exchange));
            write(
                    exchange,
                    platform.updateIdentity(decode(remainder), request, context)
                            .toCompletableFuture()
                            .join());
            return;
        }
        exchange.sendResponseHeaders(405, -1);
        exchange.close();
    }

    private static void didDocument(HttpExchange exchange, AepPlatform platform) throws IOException {
        String prefix = "/agents/";
        String path = exchange.getRequestURI().getRawPath();
        if (!HTTP_GET.equals(exchange.getRequestMethod()) || !path.startsWith(prefix) || !path.endsWith("/did.json")) {
            exchange.sendResponseHeaders(404, -1);
            exchange.close();
            return;
        }
        String agent = decode(path.substring(prefix.length(), path.length() - "/did.json".length()));
        write(
                exchange,
                platform.getDidDocument(agent, new PlatformRequestContext(null, null))
                        .toCompletableFuture()
                        .join());
    }

    private static PlatformIdentityListQuery listQuery(String rawQuery) {
        Map<String, String> values = query(rawQuery);
        ManagedAgentStatus status =
                values.containsKey("status") ? ManagedAgentStatus.fromValue(values.get("status")) : null;
        return new PlatformIdentityListQuery(
                Boolean.parseBoolean(values.getOrDefault("descending", "false")),
                Integer.parseInt(values.getOrDefault("limit", "100")),
                Integer.parseInt(values.getOrDefault("offset", "0")),
                values.get("service_did"),
                status);
    }

    private static PlatformRequestContext platformContext(HttpExchange exchange) {
        String authorization = exchange.getRequestHeaders().getFirst("Authorization");
        String principal = PLATFORM_AUTHORIZATION.equals(authorization) ? "demo-agent" : null;
        return new PlatformRequestContext(
                principal, exchange.getRequestHeaders().getFirst("Idempotency-Key"));
    }

    private static HttpResponse<String> send(
            JdkAepTransport transport, URI uri, String method, String body, AgentAuthentication authentication)
            throws IOException, InterruptedException {
        HttpRequest.Builder request = HttpRequest.newBuilder(uri);
        authentication.headers().forEach((name, values) -> values.forEach(value -> request.header(name, value)));
        request.method(
                method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        return transport.send(request.build());
    }

    private static void write(HttpExchange exchange, PlatformResponse<?> response) throws IOException {
        response.headers()
                .forEach((name, values) ->
                        values.forEach(value -> exchange.getResponseHeaders().add(name, value)));
        Object body = response.body() == null ? response.problem() : response.body();
        json(exchange, response.status(), response.contentType(), body);
    }

    private static void json(HttpExchange exchange, int status, String contentType, Object value) throws IOException {
        byte[] encoded = AepJson.write(value).getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", contentType);
        exchange.sendResponseHeaders(status, encoded.length);
        try (exchange;
                var output = exchange.getResponseBody()) {
            output.write(encoded);
        }
    }

    private static String body(HttpExchange exchange) throws IOException {
        byte[] bytes = exchange.getRequestBody().readNBytes(MAXIMUM_BODY_BYTES + 1);
        if (bytes.length > MAXIMUM_BODY_BYTES) throw new IllegalArgumentException("Request body is too large.");
        return new String(bytes, StandardCharsets.UTF_8);
    }

    private static Map<String, String> query(String rawQuery) {
        Map<String, String> values = new LinkedHashMap<>();
        if (rawQuery == null || rawQuery.isEmpty()) return values;
        for (String pair : rawQuery.split("&")) {
            int separator = pair.indexOf('=');
            String name = separator < 0 ? pair : pair.substring(0, separator);
            String value = separator < 0 ? "" : pair.substring(separator + 1);
            values.put(decode(name), decode(value));
        }
        return values;
    }

    private static String decode(String value) {
        return URLDecoder.decode(value, StandardCharsets.UTF_8);
    }

    private static String argument(String[] arguments, String name) {
        for (int index = 1; index + 1 < arguments.length; index++) {
            if (name.equals(arguments[index])) return arguments[index + 1];
        }
        throw new IllegalArgumentException("Missing argument: " + name);
    }

    private static final class InteroperabilityKeyStore implements PlatformKeyStore {
        private final Map<String, ECKey> byIdentity = new java.util.concurrent.ConcurrentHashMap<>();
        private final Map<String, ECKey> byAgentDid = new java.util.concurrent.ConcurrentHashMap<>();

        @Override
        public CompletionStage<Void> create(PlatformIdentityRecord identity, PlatformRequestContext context) {
            ECKey key = generate(identity.keyId());
            byIdentity.put(identity.agentIdentityId(), key);
            byAgentDid.put(identity.agentDid(), key);
            return CompletableFuture.completedFuture(null);
        }

        @Override
        public CompletionStage<PlatformDidVerificationMethod> didVerificationMethod(
                PlatformIdentityRecord identity, PlatformRequestContext context) {
            PlatformDidVerificationMethod method = new PlatformDidVerificationMethod(
                    identity.agentDid(),
                    identity.keyId(),
                    key(identity.agentIdentityId()).toPublicJWK().toJSONObject(),
                    "JsonWebKey2020");
            return CompletableFuture.completedStage(method);
        }

        @Override
        public CompletionStage<String> sign(
                PlatformIdentityRecord identity, ClientAssertionClaims claims, PlatformRequestContext context) {
            ECKey key = key(identity.agentIdentityId());
            String assertion = ClientAssertions.sign(claims, key, identity.keyId(), true);
            return CompletableFuture.completedStage(assertion);
        }

        @Override
        public CompletionStage<JWK> verificationKey(PlatformIdentityRecord identity, PlatformRequestContext context) {
            JWK publicKey = key(identity.agentIdentityId()).toPublicJWK();
            return CompletableFuture.completedStage(publicKey);
        }

        CompletionStage<JWK> publicKey(String agentDid) {
            ECKey key = byAgentDid.get(agentDid);
            return key == null
                    ? CompletableFuture.failedFuture(new IllegalArgumentException("Unknown Agent DID."))
                    : CompletableFuture.completedFuture(key.toPublicJWK());
        }

        private ECKey key(String identityId) {
            ECKey key = byIdentity.get(identityId);
            if (key == null) throw new IllegalArgumentException("Unknown Agent identity.");
            return key;
        }

        private static ECKey generate(String id) {
            try {
                return new ECKeyGenerator(Curve.P_256).keyID(id).generate();
            } catch (JOSEException exception) {
                throw new IllegalStateException("Unable to create interoperability key.", exception);
            }
        }
    }
}
