package foundation.aep.agent;

import foundation.aep.core.AepJson;
import foundation.aep.core.AepValidationException;
import foundation.aep.core.PortableServiceDocument;
import foundation.aep.core.ServiceDocument;
import foundation.aep.core.ServiceDocuments;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;

public final class AepDocumentReader {
    private static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(10);
    private static final HttpClient CLIENT =
            HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();

    private AepDocumentReader() {}

    public record Result(ServiceDocument descriptor, URI webUrl, PortableServiceDocument document, String reason) {}

    public static CompletableFuture<Result> read(ServiceDocument descriptor) {
        return read(descriptor, DEFAULT_TIMEOUT);
    }

    public static CompletableFuture<Result> read(ServiceDocument descriptor, Duration timeout) {
        var issues = ServiceDocuments.descriptor(descriptor);
        if (!issues.isEmpty()) throw new AepValidationException("Service document", issues);
        Objects.requireNonNull(timeout, "timeout");
        if (timeout.isNegative() || timeout.isZero()) {
            throw new IllegalArgumentException("Document timeout must be positive");
        }
        long timeoutNanos = timeout.toNanos();
        URI webUrl = URI.create(descriptor.representations().stream()
                .filter(item -> "text/html".equals(item.mediaType()))
                .findFirst()
                .orElseThrow()
                .url());
        var portable = descriptor.representations().stream()
                .filter(item -> "application/json".equals(item.mediaType()))
                .findFirst();
        if (portable.isEmpty()) {
            return CompletableFuture.completedFuture(new Result(descriptor, webUrl, null, "not_advertised"));
        }
        Result fallback = new Result(descriptor, webUrl, null, "unavailable_or_unsupported");
        HttpRequest request = HttpRequest.newBuilder(
                        URI.create(portable.orElseThrow().url()))
                .timeout(timeout)
                .header("Accept", "application/json")
                .header("Accept-Encoding", "identity")
                .GET()
                .build();
        var exchange = CLIENT.sendAsync(request, info -> {
            requireResponse(info);
            return new LimitedBodySubscriber();
        });
        // Keep caller cancellation separate from HttpClient's cancellation-propagating futures.
        CompletableFuture<Result> result = new CompletableFuture<>();
        result.whenComplete((value, failure) -> exchange.cancel(true));
        exchange.whenComplete((response, failure) -> {
                    if (result.isDone()) return;
                    if (failure != null) {
                        result.complete(fallback);
                        return;
                    }
                    try {
                        String json = StandardCharsets.UTF_8
                                .newDecoder()
                                .decode(ByteBuffer.wrap(response.body()))
                                .toString();
                        var document = AepJson.parsePortableServiceDocument(json, descriptor.id());
                        result.complete(new Result(descriptor, webUrl, document, null));
                    } catch (CharacterCodingException | RuntimeException exception) {
                        result.complete(fallback);
                    }
                })
                .exceptionally(failure -> {
                    result.completeExceptionally(failure);
                    return null;
                });
        return result.completeOnTimeout(fallback, timeoutNanos, TimeUnit.NANOSECONDS);
    }

    private static void requireResponse(HttpResponse.ResponseInfo info) {
        String contentType = info.headers().firstValue("Content-Type").orElse("");
        String encoding = info.headers().firstValue("Content-Encoding").orElse("identity");
        String[] parts = contentType.split(";", -1);
        if (info.statusCode() < 200
                || info.statusCode() >= 300
                || !"application/json".equalsIgnoreCase(parts[0].trim())
                || !"identity".equalsIgnoreCase(encoding)) {
            throw new IllegalArgumentException("Unsupported document response");
        }
        for (int index = 1; index < parts.length; index++) {
            String[] parameter = parts[index].trim().split("=", 2);
            if ("charset".equalsIgnoreCase(parameter[0].trim())
                    && (parameter.length != 2
                            || !("utf-8".equalsIgnoreCase(parameter[1].trim())
                                    || "\"utf-8\"".equalsIgnoreCase(parameter[1].trim())))) {
                throw new IllegalArgumentException("Document must use UTF-8");
            }
        }
    }

    private static final class LimitedBodySubscriber implements HttpResponse.BodySubscriber<byte[]> {
        private final HttpResponse.BodySubscriber<byte[]> delegate = HttpResponse.BodySubscribers.ofByteArray();
        private Flow.Subscription subscription;
        private int size;

        @Override
        public CompletionStage<byte[]> getBody() {
            return delegate.getBody();
        }

        @Override
        public void onSubscribe(Flow.Subscription value) {
            subscription = value;
            delegate.onSubscribe(value);
        }

        @Override
        public void onNext(List<ByteBuffer> buffers) {
            for (ByteBuffer buffer : buffers) {
                if (buffer.remaining() > ServiceDocuments.MAX_BYTES - size) {
                    subscription.cancel();
                    delegate.onError(new IllegalArgumentException("Document exceeds one MiB"));
                    return;
                }
                size += buffer.remaining();
            }
            delegate.onNext(buffers);
        }

        @Override
        public void onError(Throwable failure) {
            delegate.onError(failure);
        }

        @Override
        public void onComplete() {
            delegate.onComplete();
        }
    }
}
