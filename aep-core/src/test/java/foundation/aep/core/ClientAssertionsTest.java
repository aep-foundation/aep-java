package foundation.aep.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

final class ClientAssertionsTest {
    private static final Instant NOW = Instant.parse("2026-09-01T12:00:00Z");

    @ParameterizedTest
    @MethodSource("keys")
    void signsAndVerifiesRequiredAlgorithms(JWK key) {
        ClientAssertionClaims claims = new ClientAssertionClaims(
                "did:web:agent.example",
                "did:web:agent.example",
                "did:web:service.example",
                AssertionOperation.ENROLL,
                NOW.getEpochSecond(),
                NOW.plusSeconds(300).getEpochSecond(),
                "assertion-1",
                null);

        String token = ClientAssertions.sign(claims, key, "did:web:agent.example#key-1");
        ClientAssertionVerification verification = ClientAssertionVerification.builder(
                        claims.audience(), claims.issuer(), claims.operation())
                .clock(Clock.fixed(NOW, ZoneOffset.UTC))
                .clockSkew(Duration.ZERO)
                .build();
        ClientAssertionClaims verified = ClientAssertions.verify(token, key.toPublicJWK(), verification);

        assertEquals(claims, verified);
        assertThrows(
                IllegalArgumentException.class,
                () -> ClientAssertions.verify(
                        token,
                        key.toPublicJWK(),
                        ClientAssertionVerification.builder(
                                        "did:web:wrong.example", claims.issuer(), claims.operation())
                                .clock(Clock.fixed(NOW, ZoneOffset.UTC))
                                .clockSkew(Duration.ZERO)
                                .build()));
    }

    @ParameterizedTest
    @MethodSource("keys")
    void rejectsExpiredAndResourceMismatchedAssertions(JWK key) {
        ClientAssertionClaims claims = new ClientAssertionClaims(
                "did:web:agent.example",
                "did:web:agent.example",
                "did:web:service.example",
                AssertionOperation.AUTHENTICATE,
                NOW.minusSeconds(600).getEpochSecond(),
                NOW.minusSeconds(300).getEpochSecond(),
                "assertion-2",
                "https://service.example/resource");
        String token = ClientAssertions.sign(claims, key, "did:web:agent.example#key-1");

        assertEquals(claims, ClientAssertions.decodeUnverified(token));
        assertThrows(
                IllegalArgumentException.class,
                () -> ClientAssertions.verify(
                        token,
                        key.toPublicJWK(),
                        ClientAssertionVerification.builder(claims.audience(), claims.issuer(), claims.operation())
                                .resource(claims.resource())
                                .clock(Clock.fixed(NOW, ZoneOffset.UTC))
                                .clockSkew(Duration.ZERO)
                                .build()));
        assertThrows(
                IllegalArgumentException.class,
                () -> ClientAssertions.verify(
                        token,
                        key.toPublicJWK(),
                        ClientAssertionVerification.builder(claims.audience(), claims.issuer(), claims.operation())
                                .resource("https://service.example/other")
                                .clock(Clock.fixed(NOW.minusSeconds(450), ZoneOffset.UTC))
                                .clockSkew(Duration.ZERO)
                                .build()));
    }

    @ParameterizedTest
    @MethodSource("keys")
    void rejectsPublicSigningKeysAndMalformedTokens(JWK key) {
        ClientAssertionClaims claims = new ClientAssertionClaims(
                "did:web:agent.example",
                "did:web:agent.example",
                "did:web:service.example",
                AssertionOperation.ENROLL,
                NOW.getEpochSecond(),
                NOW.plusSeconds(300).getEpochSecond(),
                "assertion-3",
                null);

        assertThrows(
                IllegalArgumentException.class,
                () -> ClientAssertions.sign(claims, key.toPublicJWK(), "did:web:agent.example#key-1"));
        assertThrows(IllegalArgumentException.class, () -> ClientAssertions.decodeUnverified("not-a-jwt"));
    }

    private static Stream<JWK> keys() throws JOSEException {
        return Stream.of(
                new ECKeyGenerator(Curve.P_256).generate(), new OctetKeyPairGenerator(Curve.Ed25519).generate());
    }
}
