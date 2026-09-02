package foundation.aep.platform;

import com.nimbusds.jose.jwk.JWK;
import foundation.aep.core.ClientAssertionClaims;
import java.util.concurrent.CompletionStage;

public interface PlatformKeyStore {
    CompletionStage<Void> create(PlatformIdentityRecord identity, PlatformRequestContext context);

    CompletionStage<PlatformDidVerificationMethod> didVerificationMethod(
            PlatformIdentityRecord identity, PlatformRequestContext context);

    CompletionStage<String> sign(
            PlatformIdentityRecord identity, ClientAssertionClaims claims, PlatformRequestContext context);

    CompletionStage<JWK> verificationKey(PlatformIdentityRecord identity, PlatformRequestContext context);
}
