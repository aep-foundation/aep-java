package foundation.aep.core;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

public final class ClaimSupport {
    private ClaimSupport() {}

    public static Evaluation evaluate(InspectDocument.Claims requested, Iterable<String> supportedClaimNames) {
        Set<String> supported = new HashSet<>();
        supportedClaimNames.forEach(supported::add);
        List<String> unsupportedRequired =
                filter(requested == null ? List.of() : requested.required(), supported, false);
        return new Evaluation(
                unsupportedRequired.isEmpty(),
                filter(requested == null ? List.of() : requested.optional(), supported, true),
                filter(requested == null ? List.of() : requested.preferred(), supported, true),
                unsupportedRequired);
    }

    public static List<String> missingRequired(List<String> requiredClaimNames, ClaimValues values) {
        return requiredClaimNames.stream()
                .filter(name -> values == null || !values.contains(name))
                .toList();
    }

    private static List<String> filter(List<String> values, Set<String> supported, boolean present) {
        return values.stream()
                .filter(value -> supported.contains(value) == present)
                .toList();
    }

    public record Evaluation(
            boolean canSatisfyRequired,
            List<String> supportedOptional,
            List<String> supportedPreferred,
            List<String> unsupportedRequired) {
        public Evaluation {
            supportedOptional = Copies.list(supportedOptional);
            supportedPreferred = Copies.list(supportedPreferred);
            unsupportedRequired = Copies.list(unsupportedRequired);
        }
    }
}
