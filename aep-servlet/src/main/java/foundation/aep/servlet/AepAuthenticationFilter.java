package foundation.aep.servlet;

import foundation.aep.service.AepHttpAuthenticationResult;
import foundation.aep.service.AepHttpRequest;
import foundation.aep.service.AepServiceHttpHandler;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.Objects;

public final class AepAuthenticationFilter implements Filter {
    public static final String PRINCIPAL_ATTRIBUTE = "foundation.aep.principal";

    private final AepServiceHttpHandler handler;
    private final URI publicOrigin;

    public AepAuthenticationFilter(AepServiceHttpHandler handler, URI publicOrigin) {
        this.handler = Objects.requireNonNull(handler, "handler");
        AepHttpRequest.publicUrl(publicOrigin, "/", null);
        this.publicOrigin = publicOrigin;
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain)
            throws IOException, ServletException {
        if (!(servletRequest instanceof HttpServletRequest request)
                || !(servletResponse instanceof HttpServletResponse response)) {
            throw new ServletException("AEP authentication requires an HTTP request and response.");
        }
        AepHttpRequest input = AepServletSupport.request(
                request,
                AepHttpRequest.publicUrl(publicOrigin, request.getRequestURI(), request.getQueryString()),
                false,
                handler.maximumRequestBytes());
        AepHttpAuthenticationResult result =
                handler.authenticate(input).toCompletableFuture().join();
        if (result.authenticated()) {
            request.setAttribute(PRINCIPAL_ATTRIBUTE, result.principal());
            chain.doFilter(request, response);
        } else {
            AepServletSupport.write(response, result.response());
        }
    }
}
