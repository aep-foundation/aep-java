package foundation.aep.conformance;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.function.UnaryOperator;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

/**
 * A conformance mapping that cannot fail reports every implementation as conformant, which is worse
 * than having no mapping at all. Each case here runs a mapping twice: once against the vector as the
 * specification publishes it, and once against the same vector with the expectation corrupted. A
 * mapping that reads its expectation flips; a mapping that quietly compares two constants, or two
 * fields of the vector to each other, stays true and fails this test.
 */
final class ConformanceFalsifiabilityTest {
    private static final String SERVICE = "service";
    private static final String AGENT = "agent";
    private static final String PLATFORM = "platform";

    @Test
    void agentExecutesEveryHostedIdentityVector() {
        Path vectors = specVectors();
        Assumptions.assumeTrue(vectors != null, "Set AEP_SPECS_DIR to run published-vector regression tests");
        for (String id : List.of(
                "discovery",
                "list-response",
                "provision-request",
                "provision-response",
                "provision-response-distinct-services",
                "sign-request",
                "sign-response",
                "sign-response-pending",
                "idempotency-replay-conflict")) {
            assertTrue(
                    evaluate(
                            AGENT,
                            "platform",
                            id,
                            read(vectors.resolve("platform").resolve(id + ".json"))),
                    id);
        }
    }

    @Test
    void platformAuthorizationChecksEveryPrivateOperation() {
        publishedFalsifiable(
                PLATFORM,
                "platform",
                "authorization-required",
                expected -> expected.put("management_denied_status", 200));
    }

    @Test
    void grantWireMappingChecksTheActualEndpoint() {
        falsifiable(
                AGENT, "grant-revoke", "grant-request-oauth-bearer", expected -> expected.put("path", "/incorrect"));
    }

    @Test
    void serviceExecutesGrantAndEveryRevokeVariant() {
        Path vectors = specVectors();
        Assumptions.assumeTrue(vectors != null, "Set AEP_SPECS_DIR to run published-vector regression tests");
        for (String id : List.of(
                "grant-request-oauth-bearer",
                "revoke-request-oauth-bearer",
                "revoke-request-all-grant-types",
                "revoke-request-targeted-oauth-bearer")) {
            JsonNode vector = read(vectors.resolve("grant-revoke").resolve(id + ".json"));
            assertTrue(evaluate(SERVICE, "grant-revoke", id, vector), id);
            assertTrue(evaluate(AGENT, "grant-revoke", id, vector), id);
        }
    }

    @Test
    void serviceHeaderMappingChecksMissingAndMismatchedKeys() {
        falsifiable(SERVICE, "idempotency", "command-header", expected -> expected.put("missing_or_empty_status", 200));
        falsifiable(
                SERVICE,
                "idempotency",
                "command-header",
                expected -> expected.put("mismatched_enroll_body_status", 200));
    }

    @Test
    void serviceReplayMappingExercisesGrantRevokeAndRetention() {
        publishedFalsifiable(SERVICE, "idempotency", "command-replay-conflict", expected -> {
            ((ObjectNode) expected.get("changed_command")).put("status", 200);
            return expected;
        });
        publishedFalsifiable(
                SERVICE,
                "idempotency",
                "command-replay-conflict",
                expected -> expected.put("retention_seconds_minimum", 3601));
    }

    @Test
    void serviceAssertionMappingExercisesEveryPublishedRejection() {
        publishedFalsifiable(SERVICE, "client-assertion", "validation-requirements", expected -> {
            expected.putArray("reject").add("unknown-rejection");
            return expected;
        });
    }

    @Test
    void agentOriginMappingRejectsMismatchedIdentitiesBeforeSigning() {
        publishedFalsifiable(
                AGENT, "inspect", "service-did-origin-binding", expected -> expected.put("transmit_credentials", true));
    }

    @Test
    void platformVerificationMappingChecksTheCompleteResponse() {
        publishedFalsifiable(
                PLATFORM, "platform", "verification-response-recognized", expected -> expected.put("verified", false));
        publishedFalsifiable(
                PLATFORM, "platform", "verification-response-unrecognized", expected -> expected.put("verified", true));
    }

    private static void publishedFalsifiable(
            String role, String category, String id, UnaryOperator<ObjectNode> corrupt) {
        Path vectors = specVectors();
        Assumptions.assumeTrue(vectors != null, "Set AEP_SPECS_DIR to run published-vector regression tests");
        JsonNode vector = read(vectors.resolve(category).resolve(id + ".json"));
        assertTrue(evaluate(role, category, id, vector), id);
        ObjectNode changed = vector.deepCopy();
        corrupt.apply((ObjectNode) changed.get("expected"));
        assertFalse(evaluate(role, category, id, changed), id);
    }

    @Test
    void transportRequirementsReadsTheAdvertisedMediaType() {
        falsifiable(
                SERVICE,
                "inspect",
                "transport-requirements",
                expected -> expected.put("media_type_essence", "application/json"));
    }

    @Test
    void paymentCompositionReadsEachComposition() {
        falsifiable(SERVICE, "protected-resource", "authorization-payment-composition", expected -> {
            ((ObjectNode) expected.get("mpp")).put("ambiguous", true);
            return expected;
        });
    }

    @Test
    void operationSubstitutionReadsTheRejectionCode() {
        falsifiable(
                SERVICE,
                "protected-resource",
                "operation-substitution-rejected",
                expected -> expected.put("all_other_pairs", "authentication_required"));
    }

    @Test
    void fieldSafetyReadsTheMatchingRule() {
        falsifiable(
                SERVICE,
                "protected-resource",
                "authorization-field-safety",
                expected -> expected.put("field_name_match", "case-sensitive"));
    }

    @Test
    void redirectSafetyReadsTheForwardingRule() {
        falsifiable(SERVICE, "protected-resource", "redirect-safety", expected -> {
            ((ObjectNode) expected.get("same_origin")).put("credential_forwarded", true);
            return expected;
        });
    }

    /** The mappings that already read their expectation keep doing so. */
    @Test
    void grantBeforeEnrollmentReadsTheProblemCode() {
        falsifiable(
                SERVICE,
                "grant-revoke",
                "grant-before-enroll-rejected",
                expected -> expected.put("code", "invalid_request"));
    }

    @Test
    void apiKeyHeaderReadsTheRejectionCode() {
        falsifiable(
                SERVICE,
                "protected-resource",
                "api-key-wrong-header-rejected",
                expected -> expected.put("code", "not_recognized"));
    }

    @Test
    void agentTransportReadsEveryRedirectPolicy() {
        falsifiable(
                AGENT,
                "inspect",
                "transport-requirements",
                expected -> expected.put("cross_origin_redirect", "follow"));
    }

    @Test
    void agentTransportReadsTheSchemeDowngradePolicy() {
        falsifiable(AGENT, "inspect", "transport-requirements", expected -> expected.put("scheme_downgrade", "follow"));
    }

    @Test
    void agentCommandIdempotencyReadsTheHeaderRequirement() {
        falsifiable(AGENT, "idempotency", "command-header", expected -> expected.put("header_required", false));
    }

    @Test
    void agentOperationBindingReadsEachAllowedPair() {
        falsifiable(AGENT, "protected-resource", "operation-substitution-rejected", expected -> {
            ((com.fasterxml.jackson.databind.node.ArrayNode) expected.get("allowed"))
                    .set(0, expected.textNode("enroll:protected-resource"));
            return expected;
        });
    }

    @Test
    void agentPaymentCompositionReadsEachComposition() {
        falsifiable(AGENT, "protected-resource", "authorization-payment-composition", expected -> {
            ((ObjectNode) expected.get("x402")).put("ambiguous", true);
            return expected;
        });
    }

    @Test
    void agentFieldSafetyReadsTheSelectedCarrier() {
        falsifiable(
                AGENT,
                "protected-resource",
                "authorization-field-safety",
                expected -> expected.put("redirect_new_assertion_carrier", "Authorization"));
    }

    @Test
    void agentRedirectSafetyReadsTheNewAssertionResource() {
        falsifiable(AGENT, "protected-resource", "redirect-safety", expected -> {
            ((ObjectNode) expected.get("same_origin"))
                    .put("new_authenticate_assertion_resource", "https://api.example.com/v1/orders/123");
            return expected;
        });
    }

    @Test
    void agentDiscoveryCacheReadsTheNoStoreRule() {
        falsifiable(AGENT, "caching", "public-discovery-cache", expected -> expected.put("no_store", "reuse"));
    }

    @Test
    void agentDiscoveryCacheReadsTheDefaultFreshness() {
        falsifiable(
                AGENT,
                "caching",
                "public-discovery-cache",
                expected -> expected.put("default_freshness_seconds", "30"));
    }

    @Test
    void agentDiscoveryCacheReadsTheCacheKeyRule() {
        falsifiable(AGENT, "caching", "public-discovery-cache", expected -> expected.put("cache_key", "requested-url"));
    }

    @Test
    void agentAmbiguityReadsTheFallbackRule() {
        falsifiable(AGENT, "protected-resource", "authorization-ambiguity", expected -> expected.put("fallback", true));
    }

    @Test
    void serviceAmbiguityReadsTheRejectionCode() {
        falsifiable(
                SERVICE,
                "protected-resource",
                "authorization-ambiguity",
                expected -> expected.put("code", "authentication_required"));
    }

    @Test
    void serviceCredentialFailuresReadEachDistinctCode() {
        falsifiable(
                SERVICE,
                "protected-resource",
                "assertion-and-credential-failures",
                expected -> expected.put("unsupported_method", "not_recognized"));
    }

    @Test
    void serviceCredentialFailuresReadTheMissingCredentialCode() {
        falsifiable(
                SERVICE,
                "protected-resource",
                "assertion-and-credential-failures",
                expected -> expected.put("malformed_credential", "authentication_required"));
    }

    @Test
    void openApiSecurityReadsTheCompoundDisposition() {
        falsifiable(
                AGENT,
                "openapi",
                "security-inheritance",
                expected -> expected.put("multiple_schemes_one_object", "required"));
    }

    @Test
    void openApiSecurityReadsTheUnsupportedCompoundDisposition() {
        falsifiable(
                AGENT, "openapi", "security-inheritance", expected -> expected.put("unsupported_compound", "required"));
    }

    @Test
    void openApiSecurityReadsTheInheritanceDisposition() {
        falsifiable(AGENT, "openapi", "security-inheritance", expected -> expected.put("root_inherited", "public"));
    }

    @Test
    void platformIdempotencyReadsTheConflictStatus() {
        falsifiable(
                PLATFORM,
                "platform",
                "idempotency-replay-conflict",
                expected -> expected.put("changed_input_or_operation_status", 400));
    }

    @Test
    void platformIdempotencyReadsTheConflictCode() {
        falsifiable(
                PLATFORM,
                "platform",
                "idempotency-replay-conflict",
                expected -> expected.put("changed_input_or_operation_code", "invalid_request"));
    }

    @Test
    void platformRecognizedVerificationReadsTheVerdict() {
        falsifiable(PLATFORM, "platform", "verification-response-recognized", expected -> expected.put("op", "status"));
    }

    /**
     * minimal-http publishes the Inspect document itself rather than an expectation about it, so the
     * SDK's job is to parse it and reproduce it. Changing a value corrupts both sides of the
     * comparison at once; adding a member the parser must carry through is what the round-trip is
     * actually for, and a parser that silently drops it fails.
     */
    @Test
    void inspectDocumentRoundTripReadsEveryPublishedMember() {
        JsonNode vector = Vectors.byId("minimal-http");
        assertTrue(
                evaluate(AGENT, "inspect", "minimal-http", vector),
                "the mapping rejects the Inspect document the specification publishes");
        ObjectNode corrupted = vector.deepCopy();
        ((ObjectNode) corrupted.get("expected")).put("unpreserved_member", "dropped-by-the-parser");
        assertFalse(
                evaluate(AGENT, "inspect", "minimal-http", corrupted),
                "the round-trip accepted a document member the parser silently dropped");
    }

    /**
     * verification-request's idempotency_key_header is the key the caller sends, not a value the SDK
     * produces, so corrupting it only changes the key the mapping uses and cannot falsify anything.
     * What the vector does test is that the key is required and that an exact replay returns the
     * stored result, which is asserted directly.
     */
    @Test
    void platformIdempotencyReadsTheRetentionMinimum() {
        falsifiable(
                PLATFORM,
                "platform",
                "idempotency-replay-conflict",
                expected -> expected.put("retention_seconds_minimum", "36000"));
    }

    @Test
    void platformVerificationRequiresAKeyAndReplaysIt() {
        assertTrue(
                evaluate(PLATFORM, "platform", "verification-request", Vectors.byId("verification-request")),
                "the Platform does not require an idempotency key or does not replay it exactly");
    }

    /**
     * grant-request-oauth-bearer is an input round-trip: the vector's input is the request the SDK
     * must parse and reproduce, so corrupting the expectation cannot falsify it. The input is
     * corrupted instead, and a parser that drops or renames a member fails.
     */
    @Test
    void grantRequestRoundTripReadsItsInput() {
        JsonNode vector = Vectors.byId("grant-request-oauth-bearer");
        assertTrue(
                evaluate(AGENT, "grant-revoke", "grant-request-oauth-bearer", vector),
                "the mapping rejects the Grant request the specification publishes");
        ObjectNode corrupted = vector.deepCopy();
        ((ObjectNode) corrupted.get("input")).put("unpreserved_member", "dropped-by-the-parser");
        assertFalse(
                evaluate(AGENT, "grant-revoke", "grant-request-oauth-bearer", corrupted),
                "the round-trip accepted an input member the parser silently dropped");
    }

    /**
     * assertion-and-credential-failures is a pass-through: the codes in it are what a Service
     * reports, and the Agent's obligation is to surface each unchanged. Corrupting one code to
     * another valid code therefore cannot make a correct mapping fail — the mapping would simply
     * carry the corrupted code through too. Its falsifiability is in the SDK, not the expectation, so
     * it is asserted directly rather than through the corruption harness.
     */
    @Test
    void agentCredentialFailuresSurfaceTheServiceCode() {
        assertTrue(
                evaluate(
                        AGENT,
                        "protected-resource",
                        "assertion-and-credential-failures",
                        Vectors.byId("assertion-and-credential-failures")),
                "the Agent does not carry the Service's Problem Details code through unchanged");
    }

    /**
     * The inlined vectors are copies. If the specification moves and this checkout has it, say so
     * here rather than letting the copies drift into testing a contract nobody publishes any more.
     */
    @Test
    void inlinedVectorsMatchThePublishedOnes() {
        Path vectors = specVectors();
        Assumptions.assumeTrue(
                vectors != null, "aep-specs is not checked out; set AEP_SPECS_DIR to run the drift check");
        for (Vector vector : Vectors.ALL) {
            JsonNode published = read(vectors.resolve(vector.category()).resolve(vector.id() + ".json"));
            assertTrue(
                    published.get("input").equals(vector.node().get("input")),
                    vector.id() + ": the inlined input no longer matches the published vector");
            assertTrue(
                    published.get("expected").equals(vector.node().get("expected")),
                    vector.id() + ": the inlined expectation no longer matches the published vector");
        }
    }

    private static void falsifiable(String role, String category, String id, UnaryOperator<ObjectNode> corrupt) {
        JsonNode vector = Vectors.byId(id);
        assertTrue(
                evaluate(role, category, id, vector),
                id + ": the mapping rejects the vector the specification publishes");

        ObjectNode corrupted = vector.deepCopy();
        corrupt.apply((ObjectNode) corrupted.get("expected"));
        assertFalse(
                evaluate(role, category, id, corrupted),
                id + ": the mapping accepted a corrupted expectation, so nothing about the SDK can make it fail");
    }

    private static boolean evaluate(String role, String category, String id, JsonNode vector) {
        AdapterRequest request = new AdapterRequest(
                1,
                role,
                PLATFORM.equals(role) ? "platform-hosted-identity" : "core-http",
                "required",
                new AdapterRequest.Vector(category, id),
                new AdapterRequest.TestCase(vector.get("input"), vector.get("expected")));
        return switch (role) {
            case SERVICE -> ServiceConformance.evaluate(request);
            case "agent" -> AgentConformance.evaluate(request);
            default -> PlatformConformance.evaluate(request);
        };
    }

    private static Path specVectors() {
        String configured = System.getenv("AEP_SPECS_DIR");
        List<Path> candidates = new java.util.ArrayList<>();
        if (configured != null) candidates.add(Path.of(configured));
        candidates.add(Path.of("..", "..", ".conformance", "aep-specs"));
        candidates.add(Path.of("..", "..", "..", "aep-specs"));
        for (Path candidate : candidates) {
            Path vectors = candidate.resolve("ietf").resolve("test-vectors");
            if (Files.isDirectory(vectors)) return vectors;
        }
        return null;
    }

    private static JsonNode read(Path path) {
        try {
            return ConformanceSupport.MAPPER.readTree(Files.readString(path));
        } catch (java.io.IOException exception) {
            throw new IllegalStateException("Unable to read " + path, exception);
        }
    }

    private record Vector(String category, String id, JsonNode node) {}

    /** Copies of the published vectors, verified against the specification by the drift check. */
    private static final class Vectors {
        private static final List<Vector> ALL = List.of(
                vector("inspect", "transport-requirements", """
                        {"input": {"request_url": "https://api.example.com/.well-known/aep",
                          "content_type": "Application/AEP+JSON; charset=utf-8",
                          "redirect_url": "https://api.example.com/discovery/aep"},
                         "expected": {"media_type_essence": "application/aep+json",
                          "redirect_policy": "same-scheme-host-effective-port",
                          "cross_origin_redirect": "reject", "scheme_downgrade": "reject",
                          "partial_document_after_bound": "reject"}}"""),
                vector("protected-resource", "authorization-payment-composition", """
                        {"input": {"anonymous_status": 401, "anonymous_challenge": "AEP"},
                         "expected": {"mpp": {"AEP-Authorization": "AEP compact-jws",
                            "Authorization": "Payment mpp-credential", "ambiguous": false},
                          "x402": {"AEP-Authorization": "Bearer opaque-token",
                            "PAYMENT-SIGNATURE": "x402-signature", "ambiguous": false},
                          "payment_advertised_after_aep": true}}"""),
                vector("protected-resource", "operation-substitution-rejected", """
                        {"input": {"operations": ["enroll", "grant", "revoke", "status", "authenticate"],
                          "command_endpoints": ["enroll", "grant", "revoke", "status"],
                          "protected_resource": "https://api.example.com/v1/orders"},
                         "expected": {"allowed": ["enroll:enroll", "grant:grant", "revoke:revoke",
                            "status:status", "authenticate:protected-resource"],
                          "all_other_pairs": "not_recognized"}}"""),
                vector("protected-resource", "authorization-field-safety", """
                        {"input": {"field_name": "aep-authorization", "selected_carrier": "AEP-Authorization"},
                         "expected": {"field_name_match": "case-insensitive",
                          "redirect_new_assertion_carrier": "AEP-Authorization",
                          "strip_on_disallowed_redirect": ["Authorization", "AEP-Authorization",
                            "PAYMENT-SIGNATURE", "api-key-header"],
                          "sensitive_headers_redacted": true, "cache_key_excluded": true,
                          "idempotency_fingerprint_excluded": true}}"""),
                vector("protected-resource", "redirect-safety", """
                        {"input": {"source": "https://api.example.com/v1/orders/123",
                          "same_origin": "https://api.example.com/v1/orders/124",
                          "cross_origin": "https://other.example.net/v1/orders/123"},
                         "expected": {"same_origin": {"credential_forwarded": false,
                            "new_authenticate_assertion_resource": "https://api.example.com/v1/orders/124"},
                          "cross_origin": {"anonymous_restart": true, "assertion_forwarded": false,
                            "session_credential_forwarded": false, "api_key_header_forwarded": false}}}"""),
                vector("idempotency", "command-header", """
                        {"input": {"commands": ["enroll", "grant", "revoke"],
                          "idempotency_key": "9f8a4d2e-1c3b-4f5e-8b7a-000000000000"},
                         "expected": {"enroll_body_key": "optional", "header_required": true,
                          "mismatched_enroll_body_status": 400, "missing_or_empty_code": "invalid_request",
                          "missing_or_empty_status": 400}}"""),
                vector("protected-resource", "assertion-and-credential-failures", """
                        {"input": {"cases": ["wrong_audience", "expired_assertion", "replayed_assertion",
                            "malformed_credential", "expired_credential", "unsupported_method",
                            "insufficient_scope"]},
                         "expected": {"wrong_audience": "not_recognized", "expired_assertion": "not_recognized",
                          "replayed_assertion": "not_recognized", "malformed_credential": "not_recognized",
                          "expired_credential": "not_recognized",
                          "unsupported_method": "unsupported_authentication_method",
                          "insufficient_scope": "insufficient_scope"}}"""),
                vector("grant-revoke", "grant-before-enroll-rejected", """
                        {"input": {"operation": "grant", "enrollment": "unrecognized"},
                         "expected": {"status": 401, "code": "not_recognized", "implicit_enrollment": false}}"""),
                vector("caching", "public-discovery-cache", """
                        {"input": {"metadata": ["Cache-Control", "ETag", "Last-Modified"],
                          "conditional_status": 304},
                         "expected": {"default_freshness_seconds": "300", "no_cache": "revalidate",
                          "no_store": "do-not-persist", "status_304": "reuse-validated-representation",
                          "cache_key": "final-safe-redirect-url"}}"""),
                vector("protected-resource", "authorization-ambiguity", """
                        {"input": {"cases": ["both-aep-recognized", "invalid-dedicated-plus-valid-standard",
                            "duplicate-dedicated-lines", "combined-dedicated-values"]},
                         "expected": {"code": "not_recognized", "disclosure": "none", "fallback": false,
                          "selected_credential": null}}"""),
                vector("openapi", "security-inheritance", """
                        {"input": {"security_scheme": {"type": "http", "scheme": "AEP",
                            "x-aep-authentication-method": "aep-jwt"}},
                         "expected": {"root_inherited": "required", "operation_empty_array": "public",
                          "empty_requirement_alternative": "optional-anonymous",
                          "multiple_objects": "alternatives",
                          "multiple_schemes_one_object": "all-required",
                          "unsupported_compound": "fallback-live-challenge"}}"""),
                vector("grant-revoke", "grant-request-oauth-bearer", """
                        {"input": {"grant_type": "oauth-bearer"},
                         "expected": {"method": "POST", "path": "/aep/grant",
                          "content_type": "application/aep+json", "authorization_scheme": "AEP",
                          "client_assertion_op": "grant", "body": {"grant_type": "oauth-bearer"}}}"""),
                vector("inspect", "minimal-http", """
                        {"input": {},
                         "expected": {"aep_version": "1.0",
                          "authentication": {"methods": ["aep-jwt", "oauth-bearer", "api-key", "basic"]},
                          "bindings": {"supported": ["http"]},
                          "claims": {"optional": [], "preferred": [], "required": ["contact.email"]},
                          "commands": {"grant_types": ["oauth-bearer", "api-key", "basic"],
                            "supported": ["enroll", "grant", "inspect", "revoke", "status"]},
                          "core": {"signing_algorithms": ["EdDSA", "ES256"]},
                          "extensions": {"supported": []},
                          "http": {"endpoint_base": "/aep/",
                            "openapi": {"path_matching": {"trailing_slash": "strict"},
                              "url": "/openapi.json"}},
                          "identity": {"methods": ["did:web"]},
                          "service": {"did": "did:web:api.example.com"}}}"""),
                vector("platform", "idempotency-replay-conflict", """
                        {"input": {"principal": "stable-principal-123",
                          "initial_sign_key": "01J0AEPSIGNINITIAL0000000001",
                          "final_sign_key": "01J0AEPSIGNFINAL000000000002",
                          "operations": ["provision", "sign", "hosted_verification"]},
                         "expected": {"retention_seconds_minimum": "3600",
                          "exact_replay": "stored_http_result",
                          "changed_input_or_operation_status": 409,
                          "changed_input_or_operation_code": "idempotency_conflict"}}"""),
                vector("platform", "verification-request", """
                        {"input": {"client_assertion": "eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDp3ZWI6cC5leGFtcGxlOmE6NFlmN3AyeFFkOSJ9.eyJhdWQiOiJkaWQ6d2ViOmFwaS5zZXJ2aWNlLmV4YW1wbGUiLCJleHAiOjE3ODM0MjU5MDAsImlhdCI6MTc4MzQyNTYwMCwiaXNzIjoiZGlkOndlYjpwLmV4YW1wbGU6YTo0WWY3cDJ4UWQ5IiwianRpIjoiMDFKMEFFUEFTU0VSVElPTjAwMDAwMDAwMDEiLCJvcCI6ImVucm9sbCIsInN1YiI6ImRpZDp3ZWI6cC5leGFtcGxlOmE6NFlmN3AyeFFkOSJ9.signature",
                          "op": "enroll", "service_did": "did:web:api.service.example"},
                         "expected": {"idempotency_key_header": "01J0AEPVERIFY0000000000001"}}"""),
                vector("platform", "verification-response-recognized", """
                        {"input": {},
                         "expected": {"agent_did": "did:web:p.example:a:4Yf7p2xQd9",
                          "agent_identity_id": "pai_01J0AEPPLATFORM000000000001", "op": "enroll",
                          "reason": "verified", "service_did": "did:web:api.service.example",
                          "status": "active", "verified": true}}"""),
                vector("protected-resource", "api-key-wrong-header-rejected", """
                        {"input": {"issued_header": "x-api-key", "presented_header": "service-api-key",
                          "api_key": "opaque-api-key"},
                         "expected": {"accepted": false, "code": "authentication_required"}}"""));

        private Vectors() {}

        static JsonNode byId(String id) {
            return ALL.stream()
                    .filter(vector -> vector.id().equals(id))
                    .findFirst()
                    .orElseThrow(() -> new IllegalArgumentException("No inlined vector: " + id))
                    .node();
        }

        private static Vector vector(String category, String id, String json) {
            return new Vector(category, id, ConformanceSupport.json(json));
        }
    }
}
