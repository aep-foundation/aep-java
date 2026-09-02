package foundation.aep.agent;

import java.net.URI;
import java.util.Map;

public interface AgentCredentialHandler {
    String authenticationMethod();

    String grantType();

    AgentCredential parse(String serviceDid, String responseJson);

    Map<String, String> authorizationHeaders(AgentCredential credential, URI resource);
}
