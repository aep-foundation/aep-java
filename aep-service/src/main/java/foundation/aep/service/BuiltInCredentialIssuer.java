package foundation.aep.service;

import foundation.aep.core.GrantRequest;
import foundation.aep.core.GrantResponses;
import java.util.concurrent.CompletionStage;

@FunctionalInterface
public interface BuiltInCredentialIssuer<T extends GrantResponses.BuiltIn> {
    CompletionStage<T> issue(GrantRequest request, GrantContext context);
}
