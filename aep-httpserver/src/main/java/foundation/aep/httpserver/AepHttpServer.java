package foundation.aep.httpserver;

import com.sun.net.httpserver.HttpContext;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import foundation.aep.core.Aep;
import foundation.aep.core.AepCommand;
import foundation.aep.core.AepJson;
import foundation.aep.core.ProblemDetails;
import foundation.aep.service.AepHttpAuthenticationResult;
import foundation.aep.service.AepHttpRequest;
import foundation.aep.service.AepHttpResponse;
import foundation.aep.service.AepServiceHttpHandler;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public final class AepHttpServer {
    public static final String PRINCIPAL_ATTRIBUTE = "foundation.aep.principal";

    private AepHttpServer() {}

    public static List<HttpContext> register(HttpServer server, AepServiceHttpHandler handler) {
        Objects.requireNonNull(server, "server");
        Objects.requireNonNull(handler, "handler");
        List<HttpContext> contexts = new ArrayList<>();
        handler.routes()
                .forEach((command, path) ->
                        contexts.add(server.createContext(path, exchange -> handle(exchange, handler, command, path))));
        return List.copyOf(contexts);
    }

    public static HttpHandler protect(AepServiceHttpHandler handler, URI publicOrigin, HttpHandler next) {
        Objects.requireNonNull(handler, "handler");
        AepHttpRequest.publicUrl(publicOrigin, "/", null);
        Objects.requireNonNull(next, "next");
        return exchange -> {
            URI url = AepHttpRequest.publicUrl(
                    publicOrigin,
                    exchange.getRequestURI().getRawPath(),
                    exchange.getRequestURI().getRawQuery());
            AepHttpRequest request = request(exchange, url, false, handler.maximumRequestBytes());
            AepHttpAuthenticationResult result = await(handler.authenticate(request));
            if (result.authenticated()) {
                exchange.setAttribute(PRINCIPAL_ATTRIBUTE, result.principal());
                next.handle(exchange);
            } else {
                write(exchange, result.response());
            }
        };
    }

    private static void handle(
            HttpExchange exchange, AepServiceHttpHandler handler, AepCommand command, String registeredPath)
            throws IOException {
        // The JDK server matches a context by prefix, so /aep/enroll also receives /aep/enrollments
        // and /aep/enroll/anything. Those are not this command's path. CORE-ERR-001 makes every AEP
        // endpoint answer errors as Problem Details, so the refusal is a document rather than
        // whatever error page the caller's client invents for an empty 404.
        if (!registeredPath.equals(exchange.getRequestURI().getRawPath())) {
            write(exchange, notFound());
            return;
        }
        // The request URL is built from the path this context is registered at, not from the raw
        // target. Resolving the target against a base would let a protocol-relative //host/path
        // decide the authority of a URL the Service treats as its own.
        AepHttpRequest request = request(
                exchange, URI.create("http://localhost").resolve(registeredPath), true, handler.maximumRequestBytes());
        write(exchange, await(handler.handle(command, request)));
    }

    private static AepHttpResponse notFound() {
        ProblemDetails problem = ProblemDetails.of("invalid_request", "AEP route not found", 404);
        return new AepHttpResponse(
                404,
                Aep.PROBLEM_MEDIA_TYPE,
                Map.of("Cache-Control", List.of("no-store")),
                AepJson.write(problem).getBytes(StandardCharsets.UTF_8));
    }

    private static AepHttpRequest request(HttpExchange exchange, URI url, boolean includeBody, int maximumRequestBytes)
            throws IOException {
        byte[] body = includeBody ? exchange.getRequestBody().readNBytes(maximumRequestBytes + 1) : new byte[0];
        Map<String, List<String>> headers = exchange.getRequestHeaders().entrySet().stream()
                .collect(java.util.stream.Collectors.toUnmodifiableMap(
                        Map.Entry::getKey, entry -> List.copyOf(entry.getValue())));
        return new AepHttpRequest(exchange.getRequestMethod(), url, headers, body);
    }

    // RFC 9110 sections 9.3.2 and 15.4.5: a HEAD response and a 304 carry the header fields a GET
    // would have produced, and no content. The JDK server needs -1 to mean "no body at all"; passing
    // a length here would make it frame content the client must not receive.
    private static void write(HttpExchange exchange, AepHttpResponse response) throws IOException {
        response.headers()
                .forEach((name, values) ->
                        values.forEach(value -> exchange.getResponseHeaders().add(name, value)));
        exchange.getResponseHeaders().set("Content-Type", response.contentType());
        byte[] body = response.body();
        boolean contentless = response.status() == 304 || "HEAD".equalsIgnoreCase(exchange.getRequestMethod());
        exchange.sendResponseHeaders(response.status(), contentless ? -1 : body.length);
        try (exchange;
                var output = exchange.getResponseBody()) {
            if (!contentless) output.write(body);
        }
    }

    private static <T> T await(java.util.concurrent.CompletionStage<T> stage) {
        return stage.toCompletableFuture().join();
    }
}
