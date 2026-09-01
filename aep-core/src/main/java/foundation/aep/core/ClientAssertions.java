package foundation.aep.core;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;

public final class ClientAssertions {
    private static final String NOT_RECOGNIZED = "AEP client assertion was not recognized.";
    private static final int REQUIRED_AUDIENCE_COUNT = 1;

    private ClientAssertions() {}

    public static String sign(ClientAssertionClaims claims, JWK privateKey, String keyId) {
        return sign(claims, privateKey, keyId, false);
    }

    public static String sign(
            ClientAssertionClaims claims, JWK privateKey, String keyId, boolean allowInsecureLoopback) {
        AepValidation.requireClientAssertionClaims(claims, allowInsecureLoopback);
        String kid = keyId == null ? claims.issuer() : keyId;
        requireKeyId(kid, claims);
        JWSAlgorithm algorithm = algorithm(privateKey);
        try {
            SignedJWT jwt = new SignedJWT(
                    new JWSHeader.Builder(algorithm)
                            .type(com.nimbusds.jose.JOSEObjectType.JWT)
                            .keyID(kid)
                            .build(),
                    toJwtClaims(claims));
            jwt.sign(signer(privateKey));
            return jwt.serialize();
        } catch (JOSEException exception) {
            throw new IllegalArgumentException("Unable to sign AEP client assertion.", exception);
        }
    }

    public static ClientAssertionClaims verify(String token, JWK publicKey, ClientAssertionVerification verification) {
        try {
            SignedJWT jwt = SignedJWT.parse(token);
            requireHeader(jwt.getHeader());
            JWSAlgorithm algorithm = algorithm(publicKey);
            if (!algorithm.equals(jwt.getHeader().getAlgorithm()) || !jwt.verify(verifier(publicKey))) {
                throw new IllegalArgumentException(NOT_RECOGNIZED);
            }
            ClientAssertionClaims claims = fromJwtClaims(jwt.getJWTClaimsSet());
            List<ValidationIssue> issues =
                    AepValidation.clientAssertionClaims(claims, verification.allowInsecureLoopback());
            if (!issues.isEmpty()) {
                throw new AepValidationException("client assertion claims", issues);
            }
            requireKeyId(jwt.getHeader().getKeyID(), claims);
            if (!claims.audience().equals(verification.audience())
                    || !claims.issuer().equals(verification.issuer())
                    || claims.operation() != verification.operation()
                    || !java.util.Objects.equals(claims.resource(), verification.resource())) {
                throw new IllegalArgumentException(NOT_RECOGNIZED);
            }
            Instant now = verification.clock().instant();
            Duration tolerance = verification.clockSkew();
            if (Instant.ofEpochSecond(claims.issuedAt()).isAfter(now.plus(tolerance))
                    || !Instant.ofEpochSecond(claims.expiresAt()).isAfter(now.minus(tolerance))) {
                throw new IllegalArgumentException(NOT_RECOGNIZED);
            }
            return claims;
        } catch (ParseException | JOSEException exception) {
            throw new IllegalArgumentException(NOT_RECOGNIZED, exception);
        }
    }

    public static ClientAssertionClaims decodeUnverified(String token) {
        try {
            return fromJwtClaims(SignedJWT.parse(token).getJWTClaimsSet());
        } catch (ParseException exception) {
            throw new IllegalArgumentException("Invalid AEP client assertion.", exception);
        }
    }

    private static JWTClaimsSet toJwtClaims(ClientAssertionClaims value) {
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .issuer(value.issuer())
                .subject(value.subject())
                .audience(value.audience())
                .issueTime(Date.from(Instant.ofEpochSecond(value.issuedAt())))
                .expirationTime(Date.from(Instant.ofEpochSecond(value.expiresAt())))
                .jwtID(value.jwtId())
                .claim("op", value.operation().value());
        if (value.resource() != null) {
            builder.claim("resource", value.resource());
        }
        return builder.build();
    }

    private static ClientAssertionClaims fromJwtClaims(JWTClaimsSet value) throws ParseException {
        List<String> audience = value.getAudience();
        if (audience.size() != REQUIRED_AUDIENCE_COUNT) {
            throw new IllegalArgumentException("AEP client assertion must contain one audience.");
        }
        var issuedAt = value.getIssueTime();
        var expiresAt = value.getExpirationTime();
        return new ClientAssertionClaims(
                value.getIssuer(),
                value.getSubject(),
                audience.get(0),
                AssertionOperation.fromValue(value.getStringClaim("op")),
                issuedAt == null ? 0 : issuedAt.toInstant().getEpochSecond(),
                expiresAt == null ? 0 : expiresAt.toInstant().getEpochSecond(),
                value.getJWTID(),
                value.getStringClaim("resource"));
    }

    private static void requireHeader(JWSHeader header) {
        if (!com.nimbusds.jose.JOSEObjectType.JWT.equals(header.getType()) || header.getKeyID() == null) {
            throw new IllegalArgumentException("Invalid AEP client assertion JOSE header.");
        }
        if (!JWSAlgorithm.ES256.equals(header.getAlgorithm()) && !JWSAlgorithm.EdDSA.equals(header.getAlgorithm())) {
            throw new IllegalArgumentException("Unsupported AEP client assertion algorithm.");
        }
    }

    private static void requireKeyId(String keyId, ClientAssertionClaims claims) {
        String did = keyId == null ? null : keyId.split("#", 2)[0];
        if (!claims.issuer().equals(did) || !claims.issuer().equals(claims.subject())) {
            throw new IllegalArgumentException("AEP kid, iss, and sub must identify the same Agent DID.");
        }
    }

    private static JWSAlgorithm algorithm(JWK key) {
        if (key instanceof ECKey ecKey && Curve.P_256.equals(ecKey.getCurve())) {
            return JWSAlgorithm.ES256;
        }
        if (key instanceof OctetKeyPair octetKeyPair && Curve.Ed25519.equals(octetKeyPair.getCurve())) {
            return JWSAlgorithm.EdDSA;
        }
        throw new IllegalArgumentException("AEP client assertions require P-256 or Ed25519 keys.");
    }

    private static JWSSigner signer(JWK key) throws JOSEException {
        if (key instanceof ECKey ecKey) {
            return new ECDSASigner(ecKey);
        }
        if (key instanceof OctetKeyPair octetKeyPair) {
            return new Ed25519Signer(octetKeyPair);
        }
        throw new IllegalArgumentException("Unsupported AEP signing key.");
    }

    private static JWSVerifier verifier(JWK key) throws JOSEException {
        if (key instanceof ECKey ecKey) {
            return new ECDSAVerifier(ecKey.toPublicJWK());
        }
        if (key instanceof OctetKeyPair octetKeyPair) {
            return new Ed25519Verifier(octetKeyPair.toPublicJWK());
        }
        throw new IllegalArgumentException("Unsupported AEP verification key.");
    }
}
