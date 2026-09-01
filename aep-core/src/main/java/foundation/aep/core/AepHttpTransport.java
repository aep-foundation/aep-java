package foundation.aep.core;

import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletionStage;

@FunctionalInterface
public interface AepHttpTransport {
    CompletionStage<Response> execute(Request request);

    record Request(String method, URI uri, Map<String, List<String>> headers, byte[] body, Duration timeout) {
        public Request {
            headers = Copies.headers(headers);
            body = body == null ? new byte[0] : body.clone();
        }

        @Override
        public byte[] body() {
            return body.clone();
        }

        @Override
        public String toString() {
            return "Request[method=" + method + ", uri=<redacted>, headerNames=" + headers.keySet() + ", bodyLength="
                    + body.length + ", timeout=" + timeout + "]";
        }
    }

    record Response(int status, Map<String, List<String>> headers, byte[] body) {
        public Response {
            headers = Copies.headers(headers);
            body = body == null ? new byte[0] : body.clone();
        }

        @Override
        public byte[] body() {
            return body.clone();
        }

        @Override
        public String toString() {
            return "Response[status=" + status + ", headerNames=" + headers.keySet() + ", bodyLength=" + body.length
                    + "]";
        }
    }
}
