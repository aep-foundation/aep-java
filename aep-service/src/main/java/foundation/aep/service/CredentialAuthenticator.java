package foundation.aep.service;

import java.util.Optional;
import java.util.concurrent.CompletionStage;

public interface CredentialAuthenticator {
    CompletionStage<Boolean> hasPresentation(CredentialAuthenticationInput input);

    CompletionStage<Optional<AuthenticatedPrincipal>> authenticate(CredentialAuthenticationInput input);
}
