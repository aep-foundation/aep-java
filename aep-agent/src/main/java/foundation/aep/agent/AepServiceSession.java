package foundation.aep.agent;

import foundation.aep.core.Aep;
import foundation.aep.core.AepCommand;
import foundation.aep.core.AepHttp;
import foundation.aep.core.AepHttpTransport;
import foundation.aep.core.AepJson;
import foundation.aep.core.AepValidation;
import foundation.aep.core.AepValidationException;
import foundation.aep.core.AgentStatus;
import foundation.aep.core.AssertionOperation;
import foundation.aep.core.ClaimValues;
import foundation.aep.core.ClientAssertionClaims;
import foundation.aep.core.DidWeb;
import foundation.aep.core.EnrollRequest;
import foundation.aep.core.EnrollResponse;
import foundation.aep.core.GrantRequest;
import foundation.aep.core.InspectDocument;
import foundation.aep.core.RevokeRequest;
import foundation.aep.core.RevokeResponse;
import foundation.aep.core.StatusResponse;
import foundation.aep.core.ValidationIssue;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

public final class AepServiceSession {
    private final AepAgent agent;
    private final URI serviceOrigin;
    private Optional<CompletableFuture<AgentInspection>> inspectionInFlight = Optional.empty();

    AepServiceSession(AepAgent agent, URI origin) {
        this.agent = agent;
        serviceOrigin = origin;
    }

    public URI origin() {
        return serviceOrigin;
    }

    public synchronized CompletableFuture<AgentInspection> inspect() {
        if (inspectionInFlight.isEmpty()) {
            CompletableFuture<AgentInspection> created =
                    future(agent.inspectCache.get(serviceOrigin)).thenCompose(this::inspectFromCache);
            inspectionInFlight = Optional.of(created);
            CompletableFuture<AgentInspection> view = created.thenApply(Function.identity());
            created.whenComplete((value, failure) -> clearInspection(created));
            return view;
        }
        return inspectionInFlight.orElseThrow().thenApply(Function.identity());
    }

    public CompletableFuture<EnrollResponse> enroll(ClaimValues claims) {
        return commandContext(AepCommand.ENROLL).thenCompose(context -> {
            requireClaims(context.inspection.document(), claims);
            String key = idempotencyKey(context, AepCommand.ENROLL, "");
            EnrollRequest request = new EnrollRequest(context.identity.did(), claims, key);
            requireValid("Enroll request", AepValidation.enrollRequest(request));
            return execute(context, AepCommand.ENROLL, "POST", request, key, AepJson::parseEnrollResponse);
        });
    }

    public CompletableFuture<StatusResponse> status() {
        return commandContext(AepCommand.STATUS)
                .thenCompose(context ->
                        execute(context, AepCommand.STATUS, "GET", null, null, AepJson::parseStatusResponse));
    }

    public CompletableFuture<StatusResponse> waitForActive(Duration interval, Duration timeout) {
        requirePositive(interval, "interval");
        requirePositive(timeout, "timeout");
        CompletableFuture<StatusResponse> result = new CompletableFuture<>();
        pollStatus(result, interval, System.nanoTime(), timeoutNanos(timeout));
        return result;
    }

    public CompletableFuture<AgentGrantResult> grant(String grantType, List<String> requestedScopes) {
        return grant(new GrantRequest(grantType, requestedScopes));
    }

    public CompletableFuture<AgentGrantResult> grant(GrantRequest request) {
        Objects.requireNonNull(request, "request");
        requireValid("Grant request", AepValidation.grantRequest(request));
        return commandContext(AepCommand.GRANT).thenCompose(context -> {
            InspectDocument.Commands commands = context.inspection.document().commands();
            if (!commands.grantTypes().contains(request.grantType())) {
                return failed(
                        "grant_type_not_advertised",
                        "AEP Service does not advertise Grant Type " + request.grantType());
            }
            if (!commands.supported().contains(AepCommand.STATUS.value())) {
                return failed("command_not_advertised", "AEP Grant requires advertised Status support");
            }
            return execute(context, AepCommand.STATUS, "GET", null, null, AepJson::parseStatusResponse)
                    .thenCompose(status -> grantActive(context, status, request));
        });
    }

    public CompletableFuture<RevokeResponse> revoke(RevokeRequest request) {
        Objects.requireNonNull(request, "request");
        requireValid("Revoke request", AepValidation.revokeRequest(request));
        return commandContext(AepCommand.REVOKE).thenCompose(context -> {
            requirePerCredentialRevoke(context.inspection.document(), request);
            String discriminator = request.credentialId() == null ? request.grantType() : request.credentialId();
            String key = idempotencyKey(context, AepCommand.REVOKE, discriminator == null ? "all" : discriminator);
            return execute(context, AepCommand.REVOKE, "POST", request, key, AepJson::parseRevokeResponse)
                    .thenCompose(response -> deleteRevoked(
                                    context.inspection.document().service().did(), request)
                            .thenApply(ignored -> response));
        });
    }

    public CompletableFuture<AgentAuthentication> authenticate(URI resource) {
        URI target = Objects.requireNonNull(resource, "resource");
        if (!AgentHttp.sameOrigin(serviceOrigin, target)) {
            return failed("origin_mismatch", "AEP credentials may only be presented to the Service origin");
        }
        return inspect().thenCompose(inspection -> authenticate(inspection, target, 0));
    }

    private CompletableFuture<AgentInspection> inspectFromCache(Optional<AgentInspectCache.Entry> cached) {
        Optional<AgentInspectCache.Entry> usable =
                cached.filter(entry -> AgentHttp.validInspectTarget(serviceOrigin, entry.documentUri()));
        Instant now = agent.clock.instant();
        if (usable.isPresent() && usable.orElseThrow().expiresAt().isAfter(now)) {
            return CompletableFuture.completedFuture(parseInspection(
                    usable.orElseThrow().json(), usable.orElseThrow().documentUri()));
        }
        Map<String, String> conditional = new LinkedHashMap<>();
        usable.map(AgentInspectCache.Entry::etag).ifPresent(value -> conditional.put("If-None-Match", value));
        usable.map(AgentInspectCache.Entry::lastModified)
                .ifPresent(value -> conditional.put("If-Modified-Since", value));
        URI requestUri = usable.map(AgentInspectCache.Entry::documentUri)
                .orElseGet(() -> serviceOrigin.resolve(Aep.WELL_KNOWN_PATH));
        return fetchInspect(requestUri, conditional, usable, 0);
    }

    private CompletableFuture<AgentInspection> fetchInspect(
            URI uri, Map<String, String> conditional, Optional<AgentInspectCache.Entry> cached, int redirects) {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Accept", Aep.MEDIA_TYPE);
        headers.putAll(conditional);
        AepHttpTransport.Request request =
                new AepHttpTransport.Request("GET", uri, AgentHttp.headers(headers), null, agent.requestTimeout);
        return future(agent.inspectTransport.execute(request)).thenCompose(response -> {
            AgentHttp.requireBodyLimit(response, agent.maximumResponseBytes);
            if (isRedirect(response.status())) {
                return followInspectRedirect(uri, response, conditional, cached, redirects);
            }
            if (response.status() == 304 && cached.isPresent()) {
                AgentInspectCache.Entry prior = cached.orElseThrow();
                AgentInspectCache.Entry refreshed = new AgentInspectCache.Entry(
                        uri,
                        prior.json(),
                        AgentHttp.header(response, "ETag").orElse(prior.etag()),
                        AgentHttp.header(response, "Last-Modified").orElse(prior.lastModified()),
                        AgentHttp.expiresAt(response, agent.clock.instant(), agent.defaultInspectFreshness));
                CompletionStage<Void> update = AgentHttp.isNoStore(response)
                        ? agent.inspectCache.delete(serviceOrigin)
                        : agent.inspectCache.put(serviceOrigin, refreshed);
                return future(update).thenApply(ignored -> parseInspection(prior.json(), uri));
            }
            if (response.status() < 200 || response.status() >= 300) {
                return failed("inspect_failed", "AEP Inspect failed", response.status());
            }
            AgentHttp.requireMediaType(response, Aep.MEDIA_TYPE);
            String json = AgentHttp.body(response);
            AgentInspection inspection = parseInspection(json, uri);
            AgentInspectCache.Entry entry = new AgentInspectCache.Entry(
                    uri,
                    json,
                    AgentHttp.header(response, "ETag").orElse(null),
                    AgentHttp.header(response, "Last-Modified").orElse(null),
                    AgentHttp.expiresAt(response, agent.clock.instant(), agent.defaultInspectFreshness));
            CompletionStage<Void> update = AgentHttp.isNoStore(response)
                    ? agent.inspectCache.delete(serviceOrigin)
                    : agent.inspectCache.put(serviceOrigin, entry);
            return future(update).thenApply(ignored -> inspection);
        });
    }

    private CompletableFuture<AgentInspection> followInspectRedirect(
            URI current,
            AepHttpTransport.Response response,
            Map<String, String> conditional,
            Optional<AgentInspectCache.Entry> cached,
            int redirects) {
        if (redirects >= agent.maximumRedirects) {
            return failed("too_many_redirects", "AEP Inspect exceeded the redirect limit");
        }
        Optional<String> location = AgentHttp.header(response, "Location");
        if (location.isEmpty()) {
            return failed("invalid_redirect", "AEP Inspect redirect is missing Location");
        }
        URI next;
        try {
            next = current.resolve(location.orElseThrow());
        } catch (IllegalArgumentException exception) {
            return failed("invalid_redirect", "AEP Inspect redirect Location is invalid", exception);
        }
        if (!AgentHttp.sameOrigin(serviceOrigin, next)) {
            return failed("cross_origin_redirect", "AEP Inspect redirect changed origin");
        }
        if (!AgentHttp.validInspectTarget(serviceOrigin, next)) {
            return failed("invalid_redirect", "AEP Inspect redirect target is invalid");
        }
        return fetchInspect(next, conditional, cached, redirects + 1);
    }

    private AgentInspection parseInspection(String json, URI documentUri) {
        InspectDocument document;
        try {
            document = AepJson.parseInspectDocument(json);
        } catch (AepValidationException exception) {
            String detail = exception.issues().stream()
                    .map(issue -> issue.path() + ": " + issue.message())
                    .collect(java.util.stream.Collectors.joining("; "));
            throw new AepAgentException("document_invalid", "AEP Inspect document is invalid: " + detail, exception);
        }
        if (!bindsServiceDid(document.service().did())) {
            throw new AepAgentException(
                    "service_identity_mismatch", "AEP Service DID does not bind the Service origin");
        }
        return new AgentInspection(serviceOrigin, documentUri, document);
    }

    private boolean bindsServiceDid(String serviceDid) {
        if (!agent.allowInsecureLoopback) {
            return DidWeb.bindsOrigin(serviceDid, serviceOrigin);
        }
        try {
            return AgentHttp.sameOrigin(DidWeb.documentUri(serviceDid, true), serviceOrigin);
        } catch (IllegalArgumentException exception) {
            return false;
        }
    }

    private CompletableFuture<CommandContext> commandContext(AepCommand command) {
        return inspect().thenCompose(inspection -> {
            if (!inspection.document().commands().supported().contains(command.value())) {
                return failed("command_not_advertised", "AEP Service does not advertise " + command.value());
            }
            String serviceDid = inspection.document().service().did();
            return future(agent.identityProvider.getOrCreate(serviceOrigin, serviceDid))
                    .thenApply(identity -> new CommandContext(inspection, identity));
        });
    }

    private <T> CompletableFuture<T> execute(
            CommandContext context,
            AepCommand command,
            String method,
            Object body,
            String idempotencyKey,
            Function<String, T> parser) {
        URI uri = AepHttp.commandUri(
                serviceOrigin, command, context.inspection.document().http().endpointBase());
        return assertion(context, command, null).thenCompose(clientAssertion -> {
            Map<String, String> headers = new LinkedHashMap<>();
            headers.put("Accept", Aep.MEDIA_TYPE);
            headers.put("Authorization", Aep.AUTHENTICATION_SCHEME + " " + clientAssertion);
            byte[] encoded = null;
            if (body != null) {
                headers.put("Content-Type", Aep.MEDIA_TYPE);
                encoded = AepJson.write(body).getBytes(StandardCharsets.UTF_8);
            }
            if (idempotencyKey != null) {
                headers.put("Idempotency-Key", idempotencyKey);
            }
            AepHttpTransport.Request request = new AepHttpTransport.Request(
                    method, uri, AgentHttp.headers(headers), encoded, agent.requestTimeout);
            return future(agent.commandTransport.execute(request)).thenCompose(response -> {
                AgentHttp.requireBodyLimit(response, agent.maximumResponseBytes);
                if (isRedirect(response.status())) {
                    return failed("command_redirect", "AEP commands must not follow redirects", response.status());
                }
                if (response.status() < 200 || response.status() >= 300) {
                    return CompletableFuture.failedFuture(AgentHttp.commandError(response));
                }
                AgentHttp.requireMediaType(response, Aep.MEDIA_TYPE);
                return CompletableFuture.completedFuture(parser.apply(AgentHttp.body(response)));
            });
        });
    }

    private CompletableFuture<String> assertion(CommandContext context, AepCommand command, URI resource) {
        Instant issued = agent.clock.instant();
        ClientAssertionClaims claims = new ClientAssertionClaims(
                context.identity.did(),
                context.identity.did(),
                context.inspection.document().service().did(),
                operation(command),
                issued.getEpochSecond(),
                issued.plus(agent.assertionLifetime).getEpochSecond(),
                requireNonBlank(agent.jwtIdSupplier.get(), "JWT ID"),
                resource == null ? null : resource.toString());
        AepValidation.requireClientAssertionClaims(claims, agent.allowInsecureLoopback);
        return future(context.identity.signer().sign(claims));
    }

    private CompletableFuture<AgentGrantResult> grantActive(
            CommandContext context, StatusResponse status, GrantRequest request) {
        if (status.status() != AgentStatus.ACTIVE) {
            return failed("enrollment_not_active", "AEP Grant requires active enrollment");
        }
        String key = idempotencyKey(context, AepCommand.GRANT, request.grantType());
        return execute(context, AepCommand.GRANT, "POST", request, key, Function.identity())
                .thenCompose(json -> storeGrant(context, request.grantType(), json));
    }

    private CompletableFuture<AgentGrantResult> storeGrant(CommandContext context, String grantType, String json) {
        Optional<AgentCredentialHandler> handler = agent.credentialHandlers.stream()
                .filter(candidate -> candidate.grantType().equals(grantType))
                .findFirst();
        if (handler.isEmpty()) {
            AepJson.requireObject(json, "Grant response");
            return CompletableFuture.completedFuture(new AgentGrantResult(grantType, json, Optional.empty()));
        }
        AgentCredential credential = handler.orElseThrow()
                .parse(context.inspection.document().service().did(), json);
        if (!credential
                        .serviceDid()
                        .equals(context.inspection.document().service().did())
                || !credential.grantType().equals(grantType)) {
            return failed("invalid_credential", "Credential handler returned mismatched credential metadata");
        }
        return future(agent.credentialStore.save(credential))
                .thenApply(ignored -> new AgentGrantResult(grantType, json, Optional.of(credential)));
    }

    private CompletionStage<Void> deleteRevoked(String serviceDid, RevokeRequest request) {
        if (request.allGrantTypes() != null) {
            return agent.credentialStore.deleteAll(serviceDid);
        }
        if (request.credentialId() != null) {
            return agent.credentialStore.delete(serviceDid, request.credentialId());
        }
        return agent.credentialStore.deleteGrantType(serviceDid, request.grantType());
    }

    private CompletableFuture<AgentAuthentication> authenticate(
            AgentInspection inspection, URI resource, int methodIndex) {
        List<String> methods = inspection.document().authentication() == null
                ? List.of()
                : inspection.document().authentication().methods();
        if (methodIndex >= methods.size()) {
            return failed("authentication_unavailable", "No advertised AEP authentication method is available");
        }
        String method = methods.get(methodIndex);
        if (Aep.AUTHENTICATION_METHOD_JWT.equals(method)) {
            return future(agent.identityProvider.getOrCreate(
                            serviceOrigin, inspection.document().service().did()))
                    .thenCompose(identity -> {
                        CommandContext context = new CommandContext(inspection, identity);
                        return assertion(context, null, resource).thenApply(clientAssertion -> {
                            String value = Aep.AUTHENTICATION_SCHEME + " " + clientAssertion;
                            return new AgentAuthentication(method, Map.of("Authorization", List.of(value)));
                        });
                    });
        }
        Optional<AgentCredentialHandler> handler = agent.credentialHandlers.stream()
                .filter(candidate -> candidate.authenticationMethod().equals(method))
                .findFirst();
        if (handler.isEmpty()) {
            return authenticate(inspection, resource, methodIndex + 1);
        }
        AgentCredentialHandler selected = handler.orElseThrow();
        return future(agent.credentialStore.find(inspection.document().service().did(), selected.grantType()))
                .thenCompose(credential -> {
                    if (credential.isEmpty()
                            || (credential.orElseThrow().expiresAt() != null
                                    && !credential.orElseThrow().expiresAt().isAfter(agent.clock.instant()))) {
                        return authenticate(inspection, resource, methodIndex + 1);
                    }
                    AgentCredential record = credential.orElseThrow();
                    if (!record.serviceDid()
                                    .equals(inspection.document().service().did())
                            || !record.grantType().equals(selected.grantType())) {
                        return failed("invalid_credential", "Stored credential metadata does not match the Service");
                    }
                    Map<String, List<String>> headers = new LinkedHashMap<>();
                    selected.authorizationHeaders(record, resource)
                            .forEach((name, value) -> headers.put(name, List.of(value)));
                    return CompletableFuture.completedFuture(new AgentAuthentication(method, headers));
                });
    }

    private void pollStatus(
            CompletableFuture<StatusResponse> result, Duration interval, long startedNanos, long timeoutNanos) {
        if (result.isDone()) {
            return;
        }
        status().whenComplete((status, failure) -> {
            if (result.isDone()) {
                return;
            }
            if (failure != null) {
                result.completeExceptionally(unwrap(failure));
                return;
            }
            if (status.status() == AgentStatus.ACTIVE) {
                result.complete(status);
                return;
            }
            if (status.status() == AgentStatus.REJECTED
                    || status.status() == AgentStatus.SUSPENDED
                    || status.status() == AgentStatus.TERMINATED) {
                result.completeExceptionally(new AepAgentException(
                        "enrollment_not_active",
                        "AEP enrollment is " + status.status().value()));
                return;
            }
            if (remainingNanos(startedNanos, timeoutNanos) <= timeoutNanos(interval)) {
                result.completeExceptionally(new AepAgentException("poll_timeout", "AEP Status polling timed out"));
                return;
            }
            CompletableFuture.runAsync(
                    () -> pollStatus(result, interval, startedNanos, timeoutNanos),
                    CompletableFuture.delayedExecutor(delayMillis(interval), TimeUnit.MILLISECONDS));
        });
    }

    private static void requireClaims(InspectDocument document, ClaimValues claims) {
        List<String> required =
                document.claims() == null ? List.of() : document.claims().required();
        List<String> missing = required.stream()
                .filter(name -> claims == null || !claims.contains(name))
                .toList();
        if (!missing.isEmpty()) {
            throw new AepAgentException(
                    "requirements_unmet", "Required Service claims are unavailable: " + String.join(", ", missing));
        }
    }

    private static void requirePerCredentialRevoke(InspectDocument document, RevokeRequest request) {
        if (request.credentialId() == null) {
            return;
        }
        InspectDocument.GrantTypeConfig config =
                document.commands().grantTypesConfig().get(request.grantType());
        if (config == null || !"true".equals(config.supportsPerCredentialRevoke())) {
            throw new AepAgentException(
                    "per_credential_revoke_unavailable", "AEP Service does not advertise per-credential Revoke");
        }
    }

    private String idempotencyKey(CommandContext context, AepCommand command, String discriminator) {
        return requireNonBlank(
                agent.idempotencyKeyProvider.keyFor(
                        context.inspection.document().service().did(), command, discriminator),
                "idempotency key");
    }

    private static AssertionOperation operation(AepCommand command) {
        if (command == null) {
            return AssertionOperation.AUTHENTICATE;
        }
        return switch (command) {
            case ENROLL -> AssertionOperation.ENROLL;
            case GRANT -> AssertionOperation.GRANT;
            case REVOKE -> AssertionOperation.REVOKE;
            case STATUS -> AssertionOperation.STATUS;
            case INSPECT -> throw new IllegalArgumentException("Inspect does not use client assertions");
        };
    }

    private static boolean isRedirect(int status) {
        return status == 301 || status == 302 || status == 303 || status == 307 || status == 308;
    }

    private static String requireNonBlank(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new AepAgentException("invalid_configuration", name + " must not be blank");
        }
        return value;
    }

    private static void requirePositive(Duration value, String name) {
        Objects.requireNonNull(value, name);
        if (value.isZero() || value.isNegative()) {
            throw new IllegalArgumentException(name + " must be positive");
        }
    }

    private synchronized void clearInspection(CompletableFuture<AgentInspection> completed) {
        if (inspectionInFlight.filter(current -> current.equals(completed)).isPresent()) {
            inspectionInFlight = Optional.empty();
        }
    }

    private static void requireValid(String documentType, List<ValidationIssue> issues) {
        if (!issues.isEmpty()) {
            throw new AepValidationException(documentType, issues);
        }
    }

    private static long timeoutNanos(Duration timeout) {
        try {
            return timeout.toNanos();
        } catch (ArithmeticException exception) {
            return Long.MAX_VALUE;
        }
    }

    private static long delayMillis(Duration duration) {
        try {
            return Math.max(1, duration.toMillis());
        } catch (ArithmeticException exception) {
            return Long.MAX_VALUE;
        }
    }

    private static long remainingNanos(long startedNanos, long timeoutNanos) {
        long elapsed = System.nanoTime() - startedNanos;
        return elapsed >= timeoutNanos ? 0 : timeoutNanos - elapsed;
    }

    private static Throwable unwrap(Throwable failure) {
        return failure instanceof java.util.concurrent.CompletionException && failure.getCause() != null
                ? failure.getCause()
                : failure;
    }

    private static <T> CompletableFuture<T> future(CompletionStage<T> stage) {
        Objects.requireNonNull(stage, "stage");
        CompletableFuture<T> result = new CompletableFuture<>();
        stage.whenComplete((value, failure) -> {
            if (failure == null) {
                result.complete(value);
            } else {
                result.completeExceptionally(unwrap(failure));
            }
        });
        return result;
    }

    private static <T> CompletableFuture<T> failed(String code, String message) {
        return CompletableFuture.failedFuture(new AepAgentException(code, message));
    }

    private static <T> CompletableFuture<T> failed(String code, String message, int status) {
        return CompletableFuture.failedFuture(new AepAgentException(code, message, status));
    }

    private static <T> CompletableFuture<T> failed(String code, String message, Throwable cause) {
        return CompletableFuture.failedFuture(new AepAgentException(code, message, cause));
    }

    private record CommandContext(AgentInspection inspection, AgentIdentity identity) {}
}
