package foundation.aep.httpserver;

import com.sun.net.httpserver.HttpContext;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import foundation.aep.core.AepCommand;
import foundation.aep.service.AepHttpAuthenticationResult;
import foundation.aep.service.AepHttpRequest;
import foundation.aep.service.AepHttpResponse;
import foundation.aep.service.AepServiceHttpHandler;
import java.io.IOException;
import java.net.URI;
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
        if (!registeredPath.equals(exchange.getRequestURI().getRawPath())) {
            exchange.sendResponseHeaders(404, -1);
            exchange.close();
            return;
        }
        AepHttpRequest request = request(
                exchange,
                URI.create("http://localhost").resolve(exchange.getRequestURI()),
                true,
                handler.maximumRequestBytes());
        write(exchange, await(handler.handle(command, request)));
    }

    private static AepHttpRequest request(HttpExchange exchange, URI url, boolean includeBody, int maximumRequestBytes)
            throws IOException {
        byte[] body = includeBody ? exchange.getRequestBody().readNBytes(maximumRequestBytes + 1) : new byte[0];
        Map<String, List<String>> headers = exchange.getRequestHeaders().entrySet().stream()
                .collect(java.util.stream.Collectors.toUnmodifiableMap(
                        Map.Entry::getKey, entry -> List.copyOf(entry.getValue())));
        return new AepHttpRequest(exchange.getRequestMethod(), url, headers, body);
    }

    private static void write(HttpExchange exchange, AepHttpResponse response) throws IOException {
        response.headers()
                .forEach((name, values) ->
                        values.forEach(value -> exchange.getResponseHeaders().add(name, value)));
        exchange.getResponseHeaders().set("Content-Type", response.contentType());
        byte[] body = response.body();
        exchange.sendResponseHeaders(response.status(), body.length);
        try (exchange;
                var output = exchange.getResponseBody()) {
            output.write(body);
        }
    }

    private static <T> T await(java.util.concurrent.CompletionStage<T> stage) {
        return stage.toCompletableFuture().join();
    }
}
