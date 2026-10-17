package foundation.aep.json.jackson3;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import foundation.aep.core.AepJsonProvider;
import foundation.aep.core.EnrollResponse;
import org.junit.jupiter.api.Test;

/** The provider turns Jackson's failures into the contract AepJson callers handle. */
final class Jackson3JsonProviderFailureTest {
    private final AepJsonProvider provider = new Jackson3JsonProvider();

    @Test
    void reportsUndecodableJsonAsAnInvalidArgument() {
        IllegalArgumentException truncated =
                assertThrows(IllegalArgumentException.class, () -> provider.decode("{", EnrollResponse.class));
        IllegalArgumentException wrongShape = assertThrows(
                IllegalArgumentException.class, () -> provider.decode("[\"active\"]", EnrollResponse.class));
        IllegalArgumentException wrongType = assertThrows(
                IllegalArgumentException.class, () -> provider.decode("{\"status\":42}", EnrollResponse.class));

        assertEquals("Unable to decode AEP JSON", truncated.getMessage());
        assertEquals("Unable to decode AEP JSON", wrongShape.getMessage());
        assertEquals("Unable to decode AEP JSON", wrongType.getMessage());
        assertTrue(truncated.getCause() instanceof tools.jackson.core.JacksonException);
    }

    @Test
    void reportsUnencodableValuesAsAnInvalidArgument() {
        IllegalArgumentException failure =
                assertThrows(IllegalArgumentException.class, () -> provider.write(new Unserializable()));

        assertEquals("Unable to encode AEP JSON", failure.getMessage());
        assertTrue(failure.getCause() instanceof tools.jackson.core.JacksonException);
    }

    /** A value whose accessor fails mid-serialization, which is how Jackson reports write errors. */
    public static final class Unserializable {
        public String getValue() {
            throw new IllegalStateException("boom");
        }
    }

    @Test
    void ignoresUnknownMembersAndOmitsAbsentOnes() {
        EnrollResponse decoded =
                provider.decode("{\"status\":\"active\",\"future_member\":{\"nested\":true}}", EnrollResponse.class);

        assertEquals(foundation.aep.core.AgentStatus.ACTIVE, decoded.status());
        assertEquals("{\"status\":\"active\"}", provider.write(decoded));
    }
}
