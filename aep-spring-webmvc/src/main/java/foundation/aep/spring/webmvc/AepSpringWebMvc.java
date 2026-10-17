package foundation.aep.spring.webmvc;

import foundation.aep.core.AepCommand;
import foundation.aep.service.AepHttpAuthenticationResult;
import foundation.aep.service.AepHttpRequest;
import foundation.aep.service.AepHttpResponse;
import foundation.aep.service.AepServiceHttpHandler;
import foundation.aep.servlet.AepServletSupport;
import java.io.IOException;
import java.net.URI;
import java.util.Objects;
import org.springframework.web.servlet.function.HandlerFilterFunction;
import org.springframework.web.servlet.function.RequestPredicate;
import org.springframework.web.servlet.function.RouterFunction;
import org.springframework.web.servlet.function.RouterFunctions;
import org.springframework.web.servlet.function.ServerRequest;
import org.springframework.web.servlet.function.ServerResponse;

public final class AepSpringWebMvc {
    public static final String PRINCIPAL_ATTRIBUTE = "foundation.aep.principal";
    private static final int NOT_MODIFIED = 304;

    private AepSpringWebMvc() {}

    public static RouterFunction<ServerResponse> routes(AepServiceHttpHandler handler) {
        Objects.requireNonNull(handler, "handler");
        RouterFunctions.Builder routes = RouterFunctions.route();
        // Advertised command paths are literal encoded paths, not Spring path patterns.
        handler.routes()
                .forEach((command, path) -> routes.route(exactly(path), request -> handle(handler, command, request)));
        return routes.build();
    }

    public static HandlerFilterFunction<ServerResponse, ServerResponse> protect(
            AepServiceHttpHandler handler, URI publicOrigin) {
        Objects.requireNonNull(handler, "handler");
        AepHttpRequest.publicUrl(publicOrigin, "/", null);
        return (request, next) -> {
            // Application handlers must retain the request thread's Spring and application context.
            AepHttpAuthenticationResult result = handler.authenticate(request(
                            handler,
                            request,
                            AepHttpRequest.publicUrl(
                                    publicOrigin,
                                    request.uri().getRawPath(),
                                    request.uri().getRawQuery()),
                            false))
                    .toCompletableFuture()
                    .join();
            if (!result.authenticated()) return rejection(result, request);
            request.attributes().put(PRINCIPAL_ATTRIBUTE, result.principal());
            return next.handle(request);
        };
    }

    private static RequestPredicate exactly(String path) {
        return request ->
                path.equals(request.requestPath().pathWithinApplication().value());
    }

    private static ServerResponse handle(AepServiceHttpHandler handler, AepCommand command, ServerRequest request)
            throws IOException {
        boolean head = "HEAD".equalsIgnoreCase(request.method().name());
        return ServerResponse.async(handler.handle(command, request(handler, request, request.uri(), true))
                .thenApply(response -> response(response, head))
                .toCompletableFuture());
    }

    private static AepHttpRequest request(
            AepServiceHttpHandler handler, ServerRequest request, URI publicUrl, boolean includeBody)
            throws IOException {
        return AepServletSupport.request(
                request.servletRequest(), publicUrl, includeBody, handler.maximumRequestBytes());
    }

    private static ServerResponse rejection(AepHttpAuthenticationResult result, ServerRequest request) {
        return response(
                result.response(), "HEAD".equalsIgnoreCase(request.method().name()));
    }

    // RFC 9110 sections 9.3.2 and 15.4.5: a HEAD response and a 304 repeat the header fields a GET
    // would have sent and carry no content. Whether the servlet stack wraps a HEAD response to
    // suppress its body depends on the framework and the container, so the adapter does it itself.
    private static ServerResponse response(AepHttpResponse response, boolean head) {
        ServerResponse.BodyBuilder builder = ServerResponse.status(response.status())
                .contentType(org.springframework.http.MediaType.parseMediaType(response.contentType()));
        response.headers().forEach((name, values) -> builder.header(name, values.toArray(String[]::new)));
        if (response.status() == NOT_MODIFIED) return builder.build();
        if (head) {
            builder.contentLength(response.body().length);
            return builder.build();
        }
        return builder.body(response.body());
    }
}
