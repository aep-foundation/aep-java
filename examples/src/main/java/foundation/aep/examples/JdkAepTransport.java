package foundation.aep.examples;

import foundation.aep.core.AepHttpTransport;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.concurrent.CompletionStage;

final class JdkAepTransport implements AepHttpTransport {
    private final HttpClient client = HttpClient.newHttpClient();

    @Override
    public CompletionStage<Response> execute(Request request) {
        HttpRequest.Builder outgoing = HttpRequest.newBuilder(request.uri()).timeout(request.timeout());
        request.headers().forEach((name, values) -> values.forEach(value -> outgoing.header(name, value)));
        HttpRequest.BodyPublisher body = request.body().length == 0
                ? HttpRequest.BodyPublishers.noBody()
                : HttpRequest.BodyPublishers.ofByteArray(request.body());
        outgoing.method(request.method(), body);
        return client.sendAsync(outgoing.build(), HttpResponse.BodyHandlers.ofByteArray())
                .thenApply(response ->
                        new Response(response.statusCode(), response.headers().map(), response.body()));
    }

    HttpResponse<String> send(HttpRequest request) throws java.io.IOException, InterruptedException {
        return client.send(request, HttpResponse.BodyHandlers.ofString());
    }
}
