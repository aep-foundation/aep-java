package foundation.aep.service;

import com.nimbusds.jose.jwk.JWK;
import foundation.aep.core.ClientAssertionClaims;
import java.util.concurrent.CompletionStage;

@FunctionalInterface
public interface ClientAssertionKeyResolver {
    CompletionStage<JWK> resolve(
            String assertion, ClientAssertionClaims unverifiedClaims, AssertionVerificationContext context);
}
