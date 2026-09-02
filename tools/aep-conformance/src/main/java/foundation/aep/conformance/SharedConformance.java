package foundation.aep.conformance;

import com.fasterxml.jackson.databind.JsonNode;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import foundation.aep.agent.AgentCredential;
import foundation.aep.agent.AgentCredentialHandler;
import foundation.aep.agent.AgentCredentialHandlers;
import foundation.aep.core.Aep;
import foundation.aep.core.AepHttp;
import foundation.aep.core.AepJson;
import foundation.aep.core.AepOpenApi;
import foundation.aep.core.AepValidation;
import foundation.aep.core.AssertionOperation;
import foundation.aep.core.AuthorizationCarrier;
import foundation.aep.core.ClaimSupport;
import foundation.aep.core.ClientAssertionClaims;
import foundation.aep.core.ClientAssertions;
import foundation.aep.core.EnrollRequest;
import foundation.aep.core.InspectDocument;
import foundation.aep.core.OpenApiAepSecurityScheme;
import foundation.aep.core.ProtectedResourceAuthorization;
import java.net.URI;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

final class SharedConformance {
    private static final Set<String> CLAIM_VALUE_VECTORS = Set.of(
            "forward-compatible-address",
            "invalid-address",
            "invalid-birthdate",
            "invalid-country-shape",
            "invalid-email-domain",
            "invalid-email-dot-string",
            "invalid-email-format",
            "invalid-empty-email",
            "invalid-mobile",
            "invalid-value-type",
            "minimal-email",
            "quoted-email");

    private SharedConformance() {}

    static Boolean evaluate(AdapterRequest request) {
        String id = request.vector().id();
        if (CLAIM_VALUE_VECTORS.contains(id)) {
            return ConformanceSupport.parseValidity(request, "claim_values", AepJson::parseClaimValues);
        }
        return switch (id) {
            case "person-contact-catalog" -> claimCatalog(request);
            case "negotiation-compatibility", "unknown-required-claim" -> claimNegotiation(request);
            case "enroll-claims" -> assertionClaims(request);
            case "validation-requirements" -> assertionValidation(request);
            case "grant-response", "grant-response-missing-credential-id" -> credentialResponse(request);
            case "request-minimal", "request-claims-catalog" -> enrollRequest(request);
            case "response-active", "response-pending-verification-owner-action" ->
                "enroll".equals(request.vector().category())
                        ? ConformanceSupport.expectedBody(request, AepJson::parseEnrollResponse)
                        : ConformanceSupport.expectedBody(request, AepJson::parseStatusResponse);
            case "response-pending-requirements" ->
                ConformanceSupport.expectedBody(request, AepJson::parseStatusResponse);
            case "grant-request-oauth-bearer" -> parseInput(request, AepJson::parseGrantRequest);
            case "revoke-request-all-grant-types",
                    "revoke-request-oauth-bearer",
                    "revoke-request-targeted-oauth-bearer",
                    "revoke-request-conflicting-targets",
                    "revoke-request-credential-id-without-grant-type" -> revokeRequest(request);
            case "revoke-response-empty" -> ConformanceSupport.expectedBody(request, AepJson::parseRevokeResponse);
            case "not-recognized-problem", "requirements-unmet-problem", "verification-pending-problem" ->
                ConformanceSupport.expectedBody(request, AepJson::parseProblemDetails);
            case "problem-details-validation" -> problemValidation(request);
            case "authenticate-command-prohibited",
                    "authenticated-command-without-identity-method",
                    "authentication-method-limit",
                    "command-without-inspect",
                    "forward-compatible-advertisements",
                    "grant-without-grant-types",
                    "invalid-advertisement-identifiers",
                    "invalid-openapi-reference",
                    "missing-signing-algorithm" ->
                ConformanceSupport.parseValidity(request, "document", AepJson::parseInspectDocument);
            case "claims-catalog-advertisement", "minimal-http" -> inspectExpected(request);
            case "default-endpoint-base" -> defaultEndpointBase(request);
            case "protocol-version" -> protocolVersion(request);
            case "service-did-origin-binding", "did-web-resolution" -> didWeb(request);
            case "authorization-carriers" -> authorizationCarriers(request);
            case "credential-presentations" -> credentialPresentations(request);
            case "inspect-authentication-methods" -> inspectAuthenticationMethods(request);
            case "path-matching" -> openApiPath(request);
            case "security-inheritance" -> openApiSecurity(request);
            case "url-resolution" -> openApiUrl(request);
            default -> null;
        };
    }

    private static boolean claimCatalog(AdapterRequest request) {
        Set<String> expected = new HashSet<>();
        request.testCase().expected().fieldNames().forEachRemaining(expected::add);
        return expected.equals(new HashSet<>(Aep.REGISTERED_CLAIMS));
    }

    private static boolean claimNegotiation(AdapterRequest request) {
        JsonNode input = request.testCase().input();
        JsonNode claims = input.has("inspect") ? input.get("inspect") : input;
        List<String> required = ConformanceSupport.strings(claims, "required");
        List<String> preferred = ConformanceSupport.strings(claims, "preferred");
        List<String> optional = ConformanceSupport.strings(claims, "optional");
        List<String> understood =
                input.has("understood") ? ConformanceSupport.strings(input, "understood") : Aep.REGISTERED_CLAIMS;
        ClaimSupport.Evaluation evaluation =
                ClaimSupport.evaluate(new InspectDocument.Claims(required, preferred, optional), understood);
        String expectedField =
                request.testCase().expected().has("can_satisfy") ? "can_satisfy" : "enrollment_requirement_satisfied";
        return evaluation.canSatisfyRequired()
                == ConformanceSupport.required(request.testCase().expected(), expectedField)
                        .asBoolean();
    }

    private static boolean assertionClaims(AdapterRequest request) {
        JsonNode input = request.testCase().input();
        ClientAssertionClaims claims = new ClientAssertionClaims(
                ConformanceSupport.text(input, "agent_did"),
                ConformanceSupport.text(input, "agent_did"),
                ConformanceSupport.text(input, "service_did"),
                AssertionOperation.fromValue(ConformanceSupport.text(input, "command")),
                ConformanceSupport.required(input, "issued_at").asLong(),
                ConformanceSupport.required(input, "expires_at").asLong(),
                ConformanceSupport.text(input, "jti"),
                input.has("resource") ? input.get("resource").asText() : null);
        return AepValidation.clientAssertionClaims(claims).isEmpty()
                && ConformanceSupport.jsonEquals(claims, request.testCase().expected());
    }

    private static boolean assertionValidation(AdapterRequest request) {
        ClientAssertionClaims claims = AepJson.parseClientAssertionClaims(
                ConformanceSupport.required(request.testCase().expected(), "claims")
                        .toString());
        JsonNode expectedHeader = ConformanceSupport.required(request.testCase().expected(), "header");
        try {
            var key = new ECKeyGenerator(Curve.P_256).generate();
            String keyId = ConformanceSupport.text(expectedHeader, "kid");
            String token = ClientAssertions.sign(claims, key, keyId);
            SignedJWT decoded = SignedJWT.parse(token);
            if (!ConformanceSupport.json(decoded.getHeader().toString()).equals(expectedHeader)
                    || !ConformanceSupport.json(AepJson.write(ClientAssertions.decodeUnverified(token)))
                            .equals(ConformanceSupport.required(
                                    request.testCase().expected(), "claims"))) {
                return false;
            }
            List<ClientAssertionClaims> invalid = List.of(
                    new ClientAssertionClaims(
                            claims.issuer(),
                            claims.subject(),
                            claims.audience(),
                            claims.operation(),
                            claims.issuedAt(),
                            claims.issuedAt() + 301,
                            claims.jwtId(),
                            claims.resource()),
                    new ClientAssertionClaims(
                            claims.issuer(),
                            claims.subject(),
                            claims.audience(),
                            claims.operation(),
                            claims.issuedAt(),
                            claims.issuedAt(),
                            claims.jwtId(),
                            claims.resource()),
                    new ClientAssertionClaims(
                            claims.issuer(),
                            claims.subject(),
                            claims.audience(),
                            AssertionOperation.AUTHENTICATE,
                            claims.issuedAt(),
                            claims.expiresAt(),
                            claims.jwtId(),
                            null),
                    new ClientAssertionClaims(
                            claims.issuer(),
                            "did:web:different.example",
                            claims.audience(),
                            claims.operation(),
                            claims.issuedAt(),
                            claims.expiresAt(),
                            claims.jwtId(),
                            claims.resource()));
            return invalid.stream()
                    .noneMatch(
                            value -> AepValidation.clientAssertionClaims(value).isEmpty());
        } catch (Exception exception) {
            throw new IllegalArgumentException("Unable to exercise client assertion signing", exception);
        }
    }

    private static boolean credentialResponse(AdapterRequest request) {
        String grantType = request.vector().category().substring("credentials/".length());
        boolean missing =
                "grant-response-missing-credential-id".equals(request.vector().id());
        JsonNode value =
                missing ? request.testCase().input() : request.testCase().expected();
        boolean expectedValid = !missing || ConformanceSupport.valid(request);
        boolean parsed;
        try {
            AepJson.parseBuiltInGrantResponse(grantType, value.toString());
            parsed = true;
        } catch (RuntimeException exception) {
            parsed = false;
        }
        return parsed == expectedValid;
    }

    private static boolean parseInput(AdapterRequest request, java.util.function.Function<String, ?> parser) {
        parser.apply(request.testCase().input().toString());
        return true;
    }

    private static boolean enrollRequest(AdapterRequest request) {
        JsonNode input = request.testCase().input();
        EnrollRequest value = new EnrollRequest(
                ConformanceSupport.text(input, "agent_did"),
                AepJson.parseClaimValues(
                        ConformanceSupport.required(input, "claims").toString()),
                ConformanceSupport.text(input, "idempotency_key"));
        return AepValidation.enrollRequest(value).isEmpty()
                && AepHttp.commandPath(foundation.aep.core.AepCommand.ENROLL, null)
                        .equals(ConformanceSupport.text(request.testCase().expected(), "path"));
    }

    private static boolean revokeRequest(AdapterRequest request) {
        boolean parsed;
        try {
            AepJson.parseRevokeRequest(request.testCase().input().toString());
            parsed = true;
        } catch (RuntimeException exception) {
            parsed = false;
        }
        boolean expected = !request.testCase().expected().has("valid") || ConformanceSupport.valid(request);
        return parsed == expected;
    }

    private static boolean problemValidation(AdapterRequest request) {
        for (JsonNode value : ConformanceSupport.required(request.testCase().input(), "cases")) {
            boolean parsed;
            try {
                AepJson.parseProblemDetails(
                        ConformanceSupport.required(value, "body").toString());
                parsed = true;
            } catch (RuntimeException exception) {
                parsed = false;
            }
            if (parsed != ConformanceSupport.required(value, "valid").asBoolean()) return false;
        }
        return true;
    }

    private static boolean inspectExpected(AdapterRequest request) {
        AepJson.parseInspectDocument(request.testCase().expected().toString());
        return true;
    }

    private static boolean defaultEndpointBase(AdapterRequest request) {
        InspectDocument document = AepJson.parseInspectDocument(
                ConformanceSupport.required(request.testCase().expected(), "document")
                        .toString());
        return AepHttp.normalizeEndpointBase(document.http().endpointBase())
                .equals(ConformanceSupport.text(request.testCase().expected(), "endpoint_base"));
    }

    private static boolean protocolVersion(AdapterRequest request) {
        for (JsonNode value : ConformanceSupport.required(request.testCase().expected(), "cases")) {
            String received = ConformanceSupport.text(value, "received");
            boolean valid = received.matches("^(?:0|[1-9][0-9]*)\\.(?:0|[1-9][0-9]*)$");
            boolean compatible = valid && AepValidation.isCompatibleVersion(received);
            if (valid != ConformanceSupport.required(value, "valid").asBoolean()
                    || compatible
                            != ConformanceSupport.required(value, "compatible").asBoolean()) return false;
        }
        return true;
    }

    private static boolean didWeb(AdapterRequest request) {
        String did = request.testCase().input().has("did")
                ? ConformanceSupport.text(request.testCase().input(), "did")
                : ConformanceSupport.text(request.testCase().input(), "matching_service_did");
        URI document = foundation.aep.core.DidWeb.documentUri(did, false);
        return "https".equals(document.getScheme())
                && (!request.testCase().expected().has("document_url")
                        || document.toString()
                                .equals(ConformanceSupport.text(
                                        request.testCase().expected(), "document_url")));
    }

    private static boolean authorizationCarriers(AdapterRequest request) {
        var fields = request.testCase().expected().fields();
        while (fields.hasNext()) {
            JsonNode expected = fields.next().getValue();
            AuthorizationCarrier carrier = Aep.AUTHORIZATION_HEADER.equals(ConformanceSupport.text(expected, "carrier"))
                    ? AuthorizationCarrier.DEDICATED
                    : AuthorizationCarrier.STANDARD;
            ProtectedResourceAuthorization parsed = AepHttp.parseAuthorization(
                    ConformanceSupport.text(expected, "scheme") + " "
                            + ConformanceSupport.text(expected, "credentials"),
                    carrier);
            var rendered = AepHttp.renderAuthorization(parsed);
            if (!rendered.containsKey(ConformanceSupport.text(expected, "carrier"))) return false;
        }
        return true;
    }

    private static boolean credentialPresentations(AdapterRequest request) {
        var fields = request.testCase().expected().fields();
        while (fields.hasNext()) {
            var entry = fields.next();
            JsonNode expected = entry.getValue();
            AgentCredentialHandler handler = AgentCredentialHandlers.builtIn().stream()
                    .filter(candidate -> candidate.grantType().equals(entry.getKey()))
                    .findFirst()
                    .orElseThrow();
            String response = credentialJson(entry.getKey(), expected);
            AgentCredential credential = handler.parse("did:web:service.example", response);
            Map<String, String> headers = handler.authorizationHeaders(
                    credential,
                    URI.create(ConformanceSupport.text(request.testCase().input(), "resource")));
            String header = ConformanceSupport.text(expected, "header");
            String rendered = headers.get(header);
            if (rendered == null) return false;
            if (expected.has("scheme") && !rendered.startsWith(ConformanceSupport.text(expected, "scheme") + " "))
                return false;
            if (expected.has("value") && !rendered.equals(ConformanceSupport.text(expected, "value"))) return false;
        }
        return true;
    }

    private static boolean inspectAuthenticationMethods(AdapterRequest request) {
        for (String name : List.of("jwt_only", "credentials_only", "ordered_mixed")) {
            JsonNode expected = ConformanceSupport.required(request.testCase().expected(), name);
            List<String> methods = ConformanceSupport.strings(expected.get("authentication"), "methods");
            InspectDocument document = inspectDocument(methods);
            if (!AepValidation.inspectDocument(document).isEmpty()
                    || !methods.equals(document.authentication().methods())) return false;
        }
        InspectDocument omitted = inspectDocument(List.of());
        return omitted.authentication() == null
                && AepValidation.inspectDocument(omitted).isEmpty();
    }

    private static String credentialJson(String grantType, JsonNode expected) {
        String common = "\"credential_id\":\"credential-1\",\"expires_at\":\"2027-01-01T00:00:00Z\",\"scopes\":[]";
        return switch (grantType) {
            case Aep.GRANT_TYPE_OAUTH_BEARER ->
                "{\"access_token\":\"opaque-token\"," + common + ",\"token_type\":\"Bearer\"}";
            case Aep.GRANT_TYPE_API_KEY ->
                "{\"api_key\":\"" + ConformanceSupport.text(expected, "value") + "\"," + common + ",\"header\":\""
                        + ConformanceSupport.text(expected, "header") + "\"}";
            case Aep.GRANT_TYPE_BASIC -> "{\"username\":\"agent\",\"password\":\"secret\"," + common + "}";
            default -> throw new IllegalArgumentException("Unknown built-in Grant Type: " + grantType);
        };
    }

    private static InspectDocument inspectDocument(List<String> methods) {
        return InspectDocument.builder()
                .version(Aep.VERSION)
                .authentication(methods.isEmpty() ? null : new InspectDocument.Authentication(methods))
                .bindings(new InspectDocument.Bindings(List.of("http")))
                .claims(new InspectDocument.Claims(List.of(), List.of(), List.of()))
                .commands(new InspectDocument.Commands(List.of("inspect"), List.of(), Map.of()))
                .core(new InspectDocument.Core(Aep.REQUIRED_SIGNING_ALGORITHMS))
                .extensions(new InspectDocument.Extensions(List.of()))
                .http(new InspectDocument.Http(Aep.DEFAULT_ENDPOINT_BASE, null))
                .identity(new InspectDocument.Identity(List.of(Aep.IDENTITY_METHOD_DID_WEB)))
                .service(new InspectDocument.Service("did:web:service.example"))
                .build();
    }

    private static boolean openApiPath(AdapterRequest request) {
        JsonNode input = request.testCase().input();
        List<String> templates = new ArrayList<>();
        input.get("templates").forEach(value -> templates.add(value.asText()));
        AepOpenApi.PathMatch selected = AepOpenApi.matchPath(
                templates,
                ConformanceSupport.text(input, "method"),
                ConformanceSupport.text(input, "path") + "?" + ConformanceSupport.text(input, "query"),
                AepOpenApi.TrailingSlashMode.STRICT);
        if (!templates.get(0).equals(selected.template())) return false;
        try {
            AepOpenApi.matchPath(List.of("/items"), "GET", "/items/", AepOpenApi.TrailingSlashMode.STRICT);
            return false;
        } catch (IllegalArgumentException expected) {
            if (!"/items"
                    .equals(AepOpenApi.matchPath(
                                    List.of("/items"), "GET", "/items/", AepOpenApi.TrailingSlashMode.EQUIVALENT)
                            .template())) return false;
        }
        try {
            AepOpenApi.matchPath(
                    List.of("/items/{id}", "/items/{name}"), "GET", "/items/1", AepOpenApi.TrailingSlashMode.STRICT);
            return false;
        } catch (IllegalArgumentException expected) {
            return true;
        }
    }

    private static boolean openApiSecurity(AdapterRequest request) {
        OpenApiAepSecurityScheme scheme = AepJson.parseOpenApiSecurityScheme(
                ConformanceSupport.required(request.testCase().input(), "security_scheme")
                        .toString());
        return Aep.AUTHENTICATION_METHOD_JWT.equals(scheme.authenticationMethod());
    }

    private static boolean openApiUrl(AdapterRequest request) {
        JsonNode input = request.testCase().input();
        URI inspect = URI.create(ConformanceSupport.text(input, "final_inspect_url"));
        URI relative = AepOpenApi.resolveDocumentUri(inspect, ConformanceSupport.text(input, "relative"));
        URI crossOrigin = AepOpenApi.resolveDocumentUri(inspect, ConformanceSupport.text(input, "cross_origin"));
        if (!relative.toString()
                        .equals(ConformanceSupport.text(request.testCase().expected(), "relative_resolved"))
                || !"https".equals(crossOrigin.getScheme())) return false;
        for (String unsafe :
                List.of("http://api.example.com/openapi.json", "https://user@api.example.com/openapi.json")) {
            try {
                AepOpenApi.resolveDocumentUri(inspect, unsafe);
                return false;
            } catch (IllegalArgumentException expected) {
                continue;
            }
        }
        return true;
    }
}
