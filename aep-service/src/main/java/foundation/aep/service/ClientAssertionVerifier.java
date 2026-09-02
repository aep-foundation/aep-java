package foundation.aep.service;

import foundation.aep.core.ClientAssertionClaims;
import foundation.aep.core.ClientAssertionVerification;
import foundation.aep.core.ClientAssertions;
import java.util.Objects;
import java.util.concurrent.CompletionStage;

@FunctionalInterface
public interface ClientAssertionVerifier {
    CompletionStage<ClientAssertionClaims> verify(String assertion, AssertionVerificationContext context);

    static ClientAssertionVerifier withKeyResolver(ClientAssertionKeyResolver resolver) {
        Objects.requireNonNull(resolver, "resolver");
        return (assertion, context) -> {
            ClientAssertionClaims unverified = ClientAssertions.decodeUnverified(assertion);
            return resolver.resolve(assertion, unverified, context)
                    .thenApply(key -> ClientAssertions.verify(
                            assertion,
                            key,
                            ClientAssertionVerification.builder(
                                            context.serviceDid(), unverified.issuer(), context.operation())
                                    .resource(context.resource())
                                    .clock(context.clock())
                                    .clockSkew(context.clockSkew())
                                    .allowInsecureLoopback(context.allowInsecureLoopback())
                                    .build()));
        };
    }
}
