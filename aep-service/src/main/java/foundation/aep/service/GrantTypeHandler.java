package foundation.aep.service;

import foundation.aep.core.GrantRequest;
import foundation.aep.core.RevokeRequest;
import java.util.concurrent.CompletionStage;

public interface GrantTypeHandler {
    CompletionStage<GrantResult> grant(GrantRequest request, GrantContext context);

    CompletionStage<Void> revoke(RevokeRequest request, RevokeContext context);
}
