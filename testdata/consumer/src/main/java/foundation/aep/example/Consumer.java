package foundation.aep.example;

import foundation.aep.core.AepJson;
import foundation.aep.core.RevokeResponse;

public final class Consumer {
    private Consumer() {}

    public static void main(String[] args) {
        String json = AepJson.write(new RevokeResponse());
        if (!"{}".equals(json)) {
            throw new IllegalStateException("Unexpected Revoke response JSON: " + json);
        }
        AepJson.parseRevokeResponse(json);
    }
}
