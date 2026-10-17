package foundation.aep.servlet;

import foundation.aep.service.AepHttpRequest;
import foundation.aep.service.AepHttpResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class AepServletSupport {
    private static final int NOT_MODIFIED = 304;

    private AepServletSupport() {}

    public static AepHttpRequest request(
            HttpServletRequest request, URI publicUrl, boolean includeBody, int maximumRequestBytes)
            throws IOException {
        Map<String, List<String>> headers = new LinkedHashMap<>();
        Enumeration<String> names = request.getHeaderNames();
        while (names != null && names.hasMoreElements()) {
            String name = names.nextElement();
            List<String> values = new ArrayList<>();
            Enumeration<String> source = request.getHeaders(name);
            while (source != null && source.hasMoreElements()) values.add(source.nextElement());
            headers.put(name, List.copyOf(values));
        }
        byte[] body = includeBody ? request.getInputStream().readNBytes(maximumRequestBytes + 1) : new byte[0];
        return new AepHttpRequest(request.getMethod(), publicUrl, headers, body);
    }

    public static void write(HttpServletResponse response, AepHttpResponse value) throws IOException {
        write(null, response, value);
    }

    // RFC 9110 section 9.3.2: a HEAD response repeats the header fields a GET would have sent,
    // Content-Length included, and carries no content. HttpServlet normally arranges that by routing
    // HEAD through doHead and a body-suppressing wrapper, but AepServlet overrides service(), so that
    // never happens and the suppression has to be explicit here.
    //
    // RFC 9110 section 15.4.5: a 304 carries the validators a GET would have produced and no content.
    // Content-Length is not among the fields it must repeat, and sending zero would describe the
    // selected representation as empty to every cache on the path.
    public static void write(HttpServletRequest request, HttpServletResponse response, AepHttpResponse value)
            throws IOException {
        value.headers().forEach((name, values) -> values.forEach(header -> response.addHeader(name, header)));
        response.setStatus(value.status());
        response.setContentType(value.contentType());
        byte[] body = value.body();
        if (value.status() == NOT_MODIFIED) return;
        response.setContentLength(body.length);
        if (request != null && "HEAD".equalsIgnoreCase(request.getMethod())) return;
        response.getOutputStream().write(body);
    }

    public static URI requestUrl(HttpServletRequest request) {
        StringBuilder value = new StringBuilder(request.getRequestURL());
        if (request.getQueryString() != null) value.append('?').append(request.getQueryString());
        return URI.create(value.toString());
    }
}
