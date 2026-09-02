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
import java.util.concurrent.CompletionException;
import org.springframework.web.servlet.function.HandlerFilterFunction;
import org.springframework.web.servlet.function.RequestPredicates;
import org.springframework.web.servlet.function.RouterFunction;
import org.springframework.web.servlet.function.RouterFunctions;
import org.springframework.web.servlet.function.ServerRequest;
import org.springframework.web.servlet.function.ServerResponse;

public final class AepSpringWebMvc {
    public static final String PRINCIPAL_ATTRIBUTE = "foundation.aep.principal";

    private AepSpringWebMvc() {}

    public static RouterFunction<ServerResponse> routes(AepServiceHttpHandler handler) {
        Objects.requireNonNull(handler, "handler");
        RouterFunctions.Builder routes = RouterFunctions.route();
        handler.routes()
                .forEach((command, path) ->
                        routes.route(RequestPredicates.path(path), request -> handle(handler, command, request)));
        return routes.build();
    }

    public static HandlerFilterFunction<ServerResponse, ServerResponse> protect(
            AepServiceHttpHandler handler, URI publicOrigin) {
        Objects.requireNonNull(handler, "handler");
        AepHttpRequest.publicUrl(publicOrigin, "/", null);
        return (request, next) -> ServerResponse.async(handler.authenticate(request(
                        handler,
                        request,
                        AepHttpRequest.publicUrl(
                                publicOrigin,
                                request.uri().getRawPath(),
                                request.uri().getRawQuery()),
                        false))
                .thenApply(result -> continueOrReject(result, request, next))
                .toCompletableFuture());
    }

    private static ServerResponse handle(AepServiceHttpHandler handler, AepCommand command, ServerRequest request)
            throws IOException {
        return ServerResponse.async(handler.handle(command, request(handler, request, request.uri(), true))
                .thenApply(AepSpringWebMvc::response)
                .toCompletableFuture());
    }

    private static AepHttpRequest request(
            AepServiceHttpHandler handler, ServerRequest request, URI publicUrl, boolean includeBody)
            throws IOException {
        return AepServletSupport.request(
                request.servletRequest(), publicUrl, includeBody, handler.maximumRequestBytes());
    }

    private static ServerResponse continueOrReject(
            AepHttpAuthenticationResult result,
            ServerRequest request,
            org.springframework.web.servlet.function.HandlerFunction<ServerResponse> next) {
        if (!result.authenticated()) return response(result.response());
        request.attributes().put(PRINCIPAL_ATTRIBUTE, result.principal());
        try {
            return next.handle(request);
        } catch (Exception exception) {
            throw new CompletionException(exception);
        }
    }

    private static ServerResponse response(AepHttpResponse response) {
        ServerResponse.BodyBuilder builder = ServerResponse.status(response.status())
                .contentType(org.springframework.http.MediaType.parseMediaType(response.contentType()));
        response.headers().forEach((name, values) -> builder.header(name, values.toArray(String[]::new)));
        return builder.body(response.body());
    }
}
