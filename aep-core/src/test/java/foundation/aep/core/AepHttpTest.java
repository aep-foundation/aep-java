package foundation.aep.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

final class AepHttpTest {
    @Test
    void composesCommandUris() {
        assertEquals(
                URI.create("https://service.example/custom/status"),
                AepHttp.commandUri(URI.create("https://service.example"), AepCommand.STATUS, "/custom"));
        assertThrows(
                IllegalArgumentException.class,
                () -> AepHttp.commandPath(AepCommand.INSPECT, Aep.DEFAULT_ENDPOINT_BASE));
    }

    @Test
    void rendersAndParsesAuthorization() {
        ProtectedResourceAuthorization authorization = new ProtectedResourceAuthorization(
                AuthorizationCarrier.DEDICATED, AuthorizationScheme.AEP, "assertion");

        assertEquals(Map.of("AEP-Authorization", "AEP assertion"), AepHttp.renderAuthorization(authorization));
        assertEquals(authorization, AepHttp.parseAuthorization("aep assertion", AuthorizationCarrier.DEDICATED));
        assertFalse(authorization.toString().contains("assertion"));
        assertThrows(
                AepAuthorizationException.class,
                () -> AepHttp.parseAuthorization("AEP first, AEP second", AuthorizationCarrier.DEDICATED));
    }

    @Test
    void transportValuesAreDeeplyImmutable() {
        List<String> values = new ArrayList<>(List.of("one"));
        Map<String, List<String>> headers = new LinkedHashMap<>();
        headers.put("X-Test", values);
        byte[] body = {1};

        AepHttpTransport.Request request =
                new AepHttpTransport.Request("GET", URI.create("https://example.com"), headers, body, Duration.ZERO);
        values.add("two");
        body[0] = 2;

        assertEquals(List.of("one"), request.headers().get("X-Test"));
        assertEquals(1, request.body()[0]);
        assertThrows(
                UnsupportedOperationException.class,
                () -> request.headers().get("X-Test").add("three"));
        assertFalse(request.toString().contains("example.com"));

        AepHttpTransport.Response response = new AepHttpTransport.Response(200, headers, body);
        body[0] = 3;
        assertEquals(2, response.body()[0]);
        assertThrows(
                UnsupportedOperationException.class,
                () -> response.headers().get("X-Test").add("four"));
    }

    @Test
    void rejectsMalformedAuthorizationPresentations() {
        assertThrows(
                AepAuthorizationException.class,
                () -> AepHttp.renderAuthorization(new ProtectedResourceAuthorization(
                        AuthorizationCarrier.STANDARD, AuthorizationScheme.BEARER, "")));
        assertThrows(AepAuthorizationException.class, () -> AepHttp.renderAuthorization(null));
        assertThrows(
                AepAuthorizationException.class,
                () -> AepHttp.renderAuthorization(new ProtectedResourceAuthorization(null, null, "credential")));
        assertThrows(IllegalArgumentException.class, () -> AepHttp.authorizationHeaderName(null));
        assertThrows(IllegalArgumentException.class, () -> AepHttp.parseAuthorization("Bearer credential", null));
        assertThrows(
                AepAuthorizationException.class, () -> AepHttp.parseAuthorization(null, AuthorizationCarrier.STANDARD));
        assertThrows(
                AepAuthorizationException.class,
                () -> AepHttp.parseAuthorization("Unknown credential", AuthorizationCarrier.STANDARD));
        assertThrows(
                AepAuthorizationException.class,
                () -> AepHttp.parseAuthorization("Bearer  credential", AuthorizationCarrier.STANDARD));
        assertThrows(
                AepAuthorizationException.class,
                () -> AepHttp.parseAuthorization("Bearer", AuthorizationCarrier.STANDARD));
    }
}
