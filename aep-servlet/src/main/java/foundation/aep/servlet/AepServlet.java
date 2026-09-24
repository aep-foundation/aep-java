package foundation.aep.servlet;

import foundation.aep.core.Aep;
import foundation.aep.core.AepCommand;
import foundation.aep.core.AepJson;
import foundation.aep.core.ProblemDetails;
import foundation.aep.service.AepHttpRequest;
import foundation.aep.service.AepHttpResponse;
import foundation.aep.service.AepServiceHttpHandler;
import jakarta.servlet.AsyncContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InvalidObjectException;
import java.io.ObjectInputStream;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletionStage;

public final class AepServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;

    private final transient AepServiceHttpHandler serviceHandler;
    private final transient Map<String, AepCommand> commandsByPath;

    public AepServlet(AepServiceHttpHandler handler) {
        serviceHandler = Objects.requireNonNull(handler, "handler");
        commandsByPath = handler.routes().entrySet().stream()
                .collect(java.util.stream.Collectors.toUnmodifiableMap(Map.Entry::getValue, Map.Entry::getKey));
    }

    private void readObject(ObjectInputStream input) throws InvalidObjectException {
        throw new InvalidObjectException("AEP servlets must be constructed with an AEP Service handler.");
    }

    @Override
    protected void service(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String path = request.getRequestURI().substring(request.getContextPath().length());
        AepCommand command = commandsByPath.get(path);
        if (command == null) {
            // CORE-ERR-001 makes every AEP endpoint answer with Problem Details. sendError hands the
            // request to the container's error page, which is HTML on most of them.
            AepServletSupport.write(request, response, notFound());
            return;
        }
        AepHttpRequest input = AepServletSupport.request(
                request, AepServletSupport.requestUrl(request), true, serviceHandler.maximumRequestBytes());
        CompletionStage<AepHttpResponse> stage = serviceHandler.handle(command, input);
        if (!request.isAsyncSupported()) {
            AepServletSupport.write(
                    request, response, stage.toCompletableFuture().join());
            return;
        }
        AsyncContext context = request.startAsync(request, response);
        stage.whenComplete((result, failure) -> {
            try {
                if (failure == null) {
                    AepServletSupport.write(request, (HttpServletResponse) context.getResponse(), result);
                } else ((HttpServletResponse) context.getResponse()).sendError(500);
            } catch (IOException ignored) {
                // The client disconnected before the asynchronous response completed.
            } catch (RuntimeException exception) {
                // Anything thrown while writing would otherwise escape into the completion machinery
                // and leave the caller holding an open request until the container times it out.
                sendErrorQuietly((HttpServletResponse) context.getResponse());
            } finally {
                context.complete();
            }
        });
    }

    private static void sendErrorQuietly(HttpServletResponse response) {
        try {
            if (!response.isCommitted()) response.sendError(500);
        } catch (IOException | IllegalStateException ignored) {
            // The response is already on its way; the container closes it.
        }
    }

    private static AepHttpResponse notFound() {
        return new AepHttpResponse(
                404,
                Aep.PROBLEM_MEDIA_TYPE,
                Map.of("Cache-Control", java.util.List.of("no-store")),
                AepJson.write(ProblemDetails.of("invalid_request", "AEP route not found", 404))
                        .getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }
}
