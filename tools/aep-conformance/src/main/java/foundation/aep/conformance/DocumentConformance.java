package foundation.aep.conformance;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import foundation.aep.core.Aep;
import foundation.aep.core.AepJson;
import foundation.aep.core.AepValidationException;
import foundation.aep.core.AgentStatus;
import foundation.aep.core.ClientAssertionClaims;
import foundation.aep.core.EnrollRequest;
import foundation.aep.core.EnrollResponse;
import foundation.aep.core.GrantRequest;
import foundation.aep.core.GrantResponses;
import foundation.aep.core.InspectDocument;
import foundation.aep.core.ServiceDocument;
import foundation.aep.core.ServiceDocuments;
import foundation.aep.service.AepService;
import foundation.aep.service.CommandOptions;
import foundation.aep.service.CredentialAuthenticationInput;
import foundation.aep.service.EnrollmentDecision;
import foundation.aep.service.EnrollmentRecord;
import foundation.aep.service.EnrollmentStore;
import foundation.aep.service.ServiceCredentialRecord;
import foundation.aep.service.ServiceCredentialStore;
import foundation.aep.service.ServiceResponse;
import foundation.aep.service.StoredCredentialGrantTypes;
import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicInteger;

final class DocumentConformance {
    private static final String CONTENT = "content";
    private static final String TITLE = "title";
    private static final String ACKNOWLEDGED = "acknowledged_document_ids";
    private static final String REQUIRED_IDS = "required_document_ids";
    private static final String HTTP_STATUS = "http_status";
    private static final String OPERATIONS = "operations";
    private static final String NAME = "name";
    private static final String CLAIMS = "claims";
    private static final String ENROLL_REQUESTS = "enroll_requests";
    private static final String CREDENTIAL_IDS = "credential_ids";
    private static final String AUTHORIZATION = "Authorization";
    private static final String SERVICE_DID = "did:example:service";
    private static final String ENROLLMENT_LIFECYCLE = "enrollment-lifecycle";
    private static final String GRANT_GUIDANCE = "grant-guidance";
    private static final String UPDATE = "update";
    private static final String MISSING_CLAIMS = "missing_claims";
    private static final int HTTP_OK = 200;
    private static final Instant NOW = Instant.parse("2026-10-02T10:00:00Z");

    private DocumentConformance() {}

    static boolean evaluate(AdapterRequest request) {
        if (ENROLLMENT_LIFECYCLE.equals(request.vector().id())) return lifecycle(request);
        if (GRANT_GUIDANCE.equals(request.vector().id())) return guidance(request);
        JsonNode input = request.testCase().input();
        JsonNode cases = ConformanceSupport.required(input, "cases");
        JsonNode expected = ConformanceSupport.required(request.testCase().expected(), "cases");
        if (!cases.isArray() || cases.isEmpty() || cases.size() != expected.size()) return false;
        for (int index = 0; index < cases.size(); index++) {
            JsonNode item = cases.get(index);
            boolean valid =
                    switch (request.vector().id()) {
                        case "wire-shapes" ->
                            wire(ConformanceSupport.text(item, "schema"), ConformanceSupport.required(item, "value"));
                        case "structural-limits" -> structural(input, item);
                        default -> throw new IllegalArgumentException("Unsupported document vector");
                    };
            if (!item.get("name").equals(expected.get(index).get("name"))
                    || valid
                            != ConformanceSupport.required(expected.get(index), "valid")
                                    .asBoolean()) return false;
        }
        return true;
    }

    private static boolean lifecycle(AdapterRequest request) {
        JsonNode input = request.testCase().input();
        JsonNode initial = ConformanceSupport.required(input, "existing");
        Fixture fixture = new Fixture(
                ConformanceSupport.text(initial, "agent_did"),
                ConformanceSupport.strings(input, "current_required_ids"),
                List.of());
        EnrollmentRecord original = EnrollmentRecord.builder(
                        fixture.agentDid,
                        ConformanceSupport.text(initial, "enrollment_id"),
                        AgentStatus.fromValue(ConformanceSupport.text(initial, "status")),
                        Instant.parse(ConformanceSupport.text(initial, "created")))
                .since(Instant.parse(ConformanceSupport.text(initial, "since")))
                .claims(AepJson.parseClaimValues(initial.get(CLAIMS).toString()))
                .acknowledgedDocumentIds(ConformanceSupport.strings(initial, ACKNOWLEDGED))
                .build();
        fixture.save(original);
        List<String> credentialIds = ConformanceSupport.strings(initial, CREDENTIAL_IDS);
        for (String id : credentialIds)
            fixture.credentials
                    .save(new ServiceCredentialRecord(
                            fixture.agentDid,
                            NOW,
                            credential(id),
                            id,
                            NOW.plusSeconds(3600),
                            Aep.GRANT_TYPE_OAUTH_BEARER))
                    .toCompletableFuture()
                    .join();
        ObjectNode actual = ConformanceSupport.MAPPER.createObjectNode();
        ArrayNode results = actual.putArray(OPERATIONS);
        for (JsonNode operation : ConformanceSupport.required(input, OPERATIONS)) {
            if (operation.has("mark_required"))
                fixture.save(copy(fixture.record())
                        .requiredDocumentIds(ConformanceSupport.strings(operation, "mark_required"))
                        .build());
            EnrollmentRecord before = fixture.record();
            int effects = fixture.policyEffects.get();
            ServiceResponse<EnrollResponse> response =
                    fixture.enroll(operation, ConformanceSupport.text(operation, "key"));
            EnrollmentRecord after = fixture.record();
            ObjectNode outcome = response(response).put(NAME, ConformanceSupport.text(operation, NAME));
            outcome.set("stored_ids", ConformanceSupport.MAPPER.valueToTree(after.acknowledgedDocumentIds()));
            outcome.put("policy_effects_repeated", fixture.policyEffects.get() != effects);
            outcome.put("mutated", !after.equals(before));
            outcome.put("requirement_satisfied", after.requiredDocumentIds().isEmpty());
            results.add(outcome);
            if (UPDATE.equals(ConformanceSupport.text(operation, NAME))) {
                actual.set(
                        "outstanding_ids_after_update",
                        ConformanceSupport.MAPPER.valueToTree(
                                fixture.grant().problem().requiredDocumentIds()));
            }
        }
        EnrollmentRecord updated = fixture.record();
        actual.put(
                "identity_preserved",
                original.agentDid().equals(updated.agentDid())
                        && original.enrollmentId().equals(updated.enrollmentId()));
        actual.put("creation_preserved", original.createdAt().equals(updated.createdAt()));
        actual.put("unchanged_state_timestamp_preserved", original.since().equals(updated.since()));
        actual.set(CLAIMS, ConformanceSupport.json(AepJson.write(updated.claims())));
        ArrayNode retained = actual.putArray(CREDENTIAL_IDS);
        for (String id : credentialIds)
            fixture.credentials
                    .authenticate(
                            Aep.GRANT_TYPE_OAUTH_BEARER,
                            new CredentialAuthenticationInput(
                                    Map.of(AUTHORIZATION, List.of("Bearer " + id)),
                                    "GET",
                                    URI.create("https://service.example/private"),
                                    NOW))
                    .toCompletableFuture()
                    .join()
                    .ifPresent(match -> retained.add(match.credentialId()));
        boolean preserved = true;
        for (String status : ConformanceSupport.strings(input, "lifecycle_states")) {
            AgentStatus state = AgentStatus.fromValue(status);
            fixture.save(copy(updated).status(state).build());
            ObjectNode empty = ConformanceSupport.MAPPER.createObjectNode();
            empty.putArray(ACKNOWLEDGED);
            ServiceResponse<EnrollResponse> result = fixture.enroll(empty, "state-" + status);
            preserved &= result.status() == HTTP_OK
                    && fixture.record().status() == state
                    && updated.since().equals(fixture.record().since());
        }
        actual.put("unrelated_lifecycle_states_preserved", preserved);
        return matches(actual, request.testCase().expected());
    }

    private static boolean guidance(AdapterRequest request) {
        JsonNode input = request.testCase().input();
        Fixture fixture = new Fixture(
                "did:example:agent",
                ConformanceSupport.strings(input, REQUIRED_IDS),
                ConformanceSupport.strings(input, MISSING_CLAIMS));
        if (input.path("recognized").asBoolean())
            fixture.save(EnrollmentRecord.builder(fixture.agentDid, "existing", AgentStatus.ACTIVE, NOW)
                    .build());
        var grant = fixture.grant();
        ObjectNode actual = ConformanceSupport.MAPPER
                .createObjectNode()
                .put("grant_status", grant.status())
                .put("credential_issued", fixture.issued.get() != 0);
        if (grant.problem() == null
                || !matches(
                        ConformanceSupport.json(AepJson.write(grant.problem())),
                        ConformanceSupport.required(input, "problem"),
                        TITLE)) return false;
        Fixture unknown = new Fixture(
                fixture.agentDid,
                ConformanceSupport.strings(input, REQUIRED_IDS),
                ConformanceSupport.strings(input, MISSING_CLAIMS));
        var unknownGrant = unknown.grant();
        actual.set(
                "unrecognized",
                response(unknownGrant)
                        .put(
                                "requirements_disclosed",
                                unknownGrant.problem().requirementsPending() != null
                                        || unknownGrant.problem().requiredDocumentIds() != null));
        ArrayNode enrollments = actual.putArray(ENROLL_REQUESTS);
        for (JsonNode value : ConformanceSupport.required(input, ENROLL_REQUESTS)) {
            Fixture separate = new Fixture(
                    fixture.agentDid,
                    ConformanceSupport.strings(input, REQUIRED_IDS),
                    ConformanceSupport.strings(input, MISSING_CLAIMS));
            var enrolled = separate.enroll(value, "enroll");
            ObjectNode observed = response(enrolled).put(NAME, ConformanceSupport.text(value, NAME));
            if (enrolled.status() == HTTP_OK)
                observed.put(
                        "missing_documents_accepted",
                        !separate.record().acknowledgedDocumentIds().isEmpty());
            enrollments.add(observed);
        }
        return matches(actual, request.testCase().expected(), "agent");
    }

    private static EnrollmentRecord.Builder copy(EnrollmentRecord value) {
        return EnrollmentRecord.builder(value.agentDid(), value.enrollmentId(), value.status(), value.createdAt())
                .claims(value.claims())
                .since(value.since())
                .updatedAt(value.updatedAt())
                .ownerActionRequired(value.ownerActionRequired())
                .requirementsPending(value.requirementsPending())
                .verificationPending(value.verificationPending())
                .acknowledgedDocumentIds(value.acknowledgedDocumentIds())
                .requiredDocumentIds(value.requiredDocumentIds());
    }

    private static ObjectNode response(ServiceResponse<?> response) {
        ObjectNode result = ConformanceSupport.MAPPER.createObjectNode().put(HTTP_STATUS, response.status());
        if (response.problem() != null) result.put("code", response.problem().code());
        if (response.body() instanceof EnrollResponse enrolled)
            result.set(ACKNOWLEDGED, ConformanceSupport.MAPPER.valueToTree(enrolled.acknowledgedDocumentIds()));
        return result;
    }

    private static boolean matches(JsonNode actual, JsonNode expected, String... ignored) {
        if (actual == null) return false;
        if (expected.isObject()) {
            var fields = expected.fields();
            while (fields.hasNext()) {
                var field = fields.next();
                if (!List.of(ignored).contains(field.getKey())
                        && !matches(actual.get(field.getKey()), field.getValue())) return false;
            }
            return true;
        }
        if (expected.isArray()) {
            if (!actual.isArray() || actual.size() != expected.size()) return false;
            for (int index = 0; index < expected.size(); index++)
                if (!matches(actual.get(index), expected.get(index))) return false;
            return true;
        }
        return actual.equals(expected);
    }

    private static GrantResponses.OAuthBearer credential(String id) {
        return new GrantResponses.OAuthBearer(id, id, NOW.plusSeconds(3600).toString(), List.of(), "opaque", "Bearer");
    }

    private static final class Fixture {
        private final String agentDid;
        private final EnrollmentStore enrollments = EnrollmentStore.inMemory();
        private final ServiceCredentialStore credentials = ServiceCredentialStore.inMemory();
        private final AtomicInteger policyEffects = new AtomicInteger();
        private final AtomicInteger issued = new AtomicInteger();
        private final AtomicInteger assertions = new AtomicInteger();
        private final AepService service;

        private Fixture(String did, List<String> required, List<String> claims) {
            agentDid = did;
            var config = new InspectDocument.GrantTypeConfig("true");
            InspectDocument document = InspectDocument.builder()
                    .version(Aep.VERSION)
                    .bindings(new InspectDocument.Bindings(List.of("http")))
                    .commands(new InspectDocument.Commands(
                            List.of("inspect", "enroll", "grant"),
                            List.of(Aep.GRANT_TYPE_OAUTH_BEARER),
                            Map.of(Aep.GRANT_TYPE_OAUTH_BEARER, config)))
                    .authentication(new InspectDocument.Authentication(List.of(Aep.GRANT_TYPE_OAUTH_BEARER)))
                    .claims(new InspectDocument.Claims(claims, List.of(), List.of()))
                    .core(new InspectDocument.Core(Aep.REQUIRED_SIGNING_ALGORITHMS))
                    .extensions(new InspectDocument.Extensions(List.of(ServiceDocuments.EXTENSION)))
                    .http(new InspectDocument.Http("/aep", null))
                    .identity(new InspectDocument.Identity(List.of("did:example")))
                    .service(new InspectDocument.Service(SERVICE_DID))
                    .serviceDocuments(required.stream()
                            .map(id -> new ServiceDocument(
                                    id,
                                    "terms_of_service",
                                    id,
                                    "required",
                                    List.of(new ServiceDocument.Representation(
                                            "text/html", "https://service.example/" + id))))
                            .toList())
                    .build();
            service = AepService.builder(
                            document,
                            (assertion, context) -> CompletableFuture.completedFuture(new ClientAssertionClaims(
                                    did,
                                    did,
                                    context.serviceDid(),
                                    context.operation(),
                                    NOW.minusSeconds(1).getEpochSecond(),
                                    NOW.plusSeconds(60).getEpochSecond(),
                                    assertion,
                                    null)))
                    .clock(Clock.fixed(NOW, ZoneOffset.UTC))
                    .enrollmentStore(enrollments)
                    .enrollmentPolicy((request, now) -> {
                        policyEffects.incrementAndGet();
                        return CompletableFuture.completedFuture(EnrollmentDecision.active());
                    })
                    .storedCredentialGrantType(StoredCredentialGrantTypes.oauthBearer(
                            config,
                            (request, context) -> {
                                issued.incrementAndGet();
                                return CompletableFuture.completedFuture(credential("issued"));
                            },
                            credentials))
                    .build();
        }

        private CommandOptions options(String key) {
            return CommandOptions.idempotent("assertion-" + assertions.incrementAndGet(), key);
        }

        private void save(EnrollmentRecord record) {
            enrollments.save(record).toCompletableFuture().join();
        }

        private EnrollmentRecord record() {
            return enrollments.find(agentDid).toCompletableFuture().join().orElseThrow();
        }

        private ServiceResponse<EnrollResponse> enroll(JsonNode input, String key) {
            EnrollRequest request = new EnrollRequest(
                    agentDid,
                    input.has(CLAIMS)
                            ? AepJson.parseClaimValues(input.get(CLAIMS).toString())
                            : null,
                    key,
                    input.has(ACKNOWLEDGED) ? ConformanceSupport.strings(input, ACKNOWLEDGED) : null);
            return service.enroll(request, options(key)).toCompletableFuture().join();
        }

        private ServiceResponse<Map<String, Object>> grant() {
            return service.grant(
                            new GrantRequest(Aep.GRANT_TYPE_OAUTH_BEARER, List.of()),
                            options("grant-" + assertions.get()))
                    .toCompletableFuture()
                    .join();
        }
    }

    private static boolean wire(String schema, JsonNode value) {
        try {
            switch (schema) {
                case "service-documents.schema.json" ->
                    AepJson.parseInspectDocument(inspect(value).toString());
                case "inspect-document.schema.json" -> AepJson.parseInspectDocument(value.toString());
                case "enroll-request.schema.json" -> AepJson.parseEnrollRequest(value.toString());
                case "enroll-response.schema.json" -> AepJson.parseEnrollResponse(value.toString());
                case "problem.schema.json" -> AepJson.parseProblemDetails(value.toString());
                case "portable-service-document.schema.json" ->
                    AepJson.parsePortableServiceDocument(
                            value.toString(), value.path("id").asText());
                default -> throw new IllegalArgumentException("Unsupported document schema");
            }
            return true;
        } catch (AepValidationException exception) {
            return false;
        }
    }

    private static ObjectNode inspect(JsonNode fields) {
        ObjectNode base = (ObjectNode) ConformanceSupport.json("""
                {"aep_version":"1.0","bindings":{"supported":["http"]},"commands":{"supported":["inspect"]},
                 "core":{"signing_algorithms":["EdDSA","ES256"]},"http":{"endpoint_base":"/aep"},
                 "identity":{"methods":[]},"service":{"did":"did:example:service"}}
                """);
        if (!fields.isObject()) throw new IllegalArgumentException("Expected Inspect members");
        fields.fields().forEachRemaining(field -> base.set(field.getKey(), field.getValue()));
        return base;
    }

    private static boolean structural(JsonNode input, JsonNode item) {
        ObjectNode descriptor = ConformanceSupport.required(input, "descriptor").deepCopy();
        ObjectNode document = ConformanceSupport.required(input, "document").deepCopy();
        ArrayNode catalog = ConformanceSupport.MAPPER.createArrayNode();
        String kind = ConformanceSupport.text(item, "kind");
        switch (kind) {
            case "catalog" -> {
                for (int index = 0; index < item.path("count").asInt(); index++)
                    catalog.add(descriptor.deepCopy().put("id", "doc-" + index));
            }
            case "duplicate-ids" -> catalog.add(descriptor).add(descriptor);
            case "duplicate-media" -> {
                ((ArrayNode) descriptor.get("representations"))
                        .add(descriptor.get("representations").get(0));
                catalog.add(descriptor);
            }
            case "blocks" -> {
                JsonNode block = document.get(CONTENT).get(0);
                for (String field : java.util.List.of(CONTENT, "summary")) {
                    ArrayNode blocks = document.putArray(field);
                    for (int index = 0; index < item.path(field + "_count").asInt(); index++) blocks.add(block);
                    if ("summary".equals(field) && blocks.isEmpty()) document.remove(field);
                }
            }
            case "sections" -> {
                for (int index = 0; index < item.path("depth").asInt(); index++) {
                    ObjectNode section = ConformanceSupport.MAPPER
                            .createObjectNode()
                            .put("type", "section")
                            .put(TITLE, "Section");
                    section.set("blocks", document.get(CONTENT));
                    document.putArray(CONTENT).add(section);
                }
            }
            case "text" ->
                ((ObjectNode) document.get(CONTENT).get(0))
                        .put("text", "a".repeat(item.path("length").asInt()));
            case "list" -> {
                ObjectNode list = document.putArray(CONTENT).addObject().put("type", "bulleted_list");
                ArrayNode items = list.putArray("items");
                for (int index = 0; index < item.path("count").asInt(); index++) items.add("Item");
            }
            case TITLE ->
                catalog.add(descriptor.put(TITLE, "a".repeat(item.path("length").asInt())));
            case "url" -> {
                String prefix = "https://example.com/";
                ((ObjectNode) descriptor.get("representations").get(0))
                        .put("url", prefix + "a".repeat(item.path("length").asInt() - prefix.length()));
                catalog.add(descriptor);
            }
            default -> throw new IllegalArgumentException("Unsupported structural bound");
        }
        if (catalog.isEmpty()) return wire("portable-service-document.schema.json", document);
        try {
            var values = new ArrayList<foundation.aep.core.ServiceDocument>();
            for (JsonNode entry : catalog) values.add(AepJson.parseServiceDocument(entry.toString()));
            return ServiceDocuments.catalog(values).isEmpty();
        } catch (AepValidationException exception) {
            return false;
        }
    }
}
