package foundation.aep.servlet;

import foundation.aep.core.AepCommand;
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
            response.sendError(404);
            return;
        }
        AepHttpRequest input = AepServletSupport.request(
                request, AepServletSupport.requestUrl(request), true, serviceHandler.maximumRequestBytes());
        CompletionStage<AepHttpResponse> stage = serviceHandler.handle(command, input);
        if (!request.isAsyncSupported()) {
            AepServletSupport.write(response, stage.toCompletableFuture().join());
            return;
        }
        AsyncContext context = request.startAsync(request, response);
        stage.whenComplete((result, failure) -> {
            try {
                if (failure == null) AepServletSupport.write((HttpServletResponse) context.getResponse(), result);
                else ((HttpServletResponse) context.getResponse()).sendError(500);
            } catch (IOException ignored) {
                // The client disconnected before the asynchronous response completed.
            } finally {
                context.complete();
            }
        });
    }
}
