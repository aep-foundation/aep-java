package foundation.aep.spring.webmvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import foundation.aep.core.Aep;
import foundation.aep.core.AgentStatus;
import foundation.aep.core.ClientAssertionClaims;
import foundation.aep.core.InspectDocument;
import foundation.aep.service.AepService;
import foundation.aep.service.AepServiceHttpHandler;
import foundation.aep.service.EnrollmentDecision;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.servlet.function.RouterFunctions;
import org.springframework.web.servlet.function.ServerResponse;

final class AepSpringWebMvcTest {
    private static final Instant NOW = Instant.parse("2026-09-01T12:00:00Z");

    @Test
    void servesInspectAndRejectsTheWrongMethod() throws Exception {
        MockMvc client = MockMvcBuilders.routerFunctions(AepSpringWebMvc.routes(new AepServiceHttpHandler(service())))
                .build();

        client.perform(get(Aep.WELL_KNOWN_PATH))
                .andExpect(status().isOk())
                .andExpect(content().contentType(Aep.MEDIA_TYPE))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("\"aep_version\"")));
        client.perform(post(Aep.WELL_KNOWN_PATH))
                .andExpect(status().isMethodNotAllowed())
                .andExpect(header().string("Allow", "GET"));
    }

    @Test
    void protectsApplicationRoutes() throws Exception {
        AepServiceHttpHandler handler = new AepServiceHttpHandler(service());
        MockMvc client = MockMvcBuilders.routerFunctions(RouterFunctions.route()
                        .GET("/orders", request -> ServerResponse.noContent().build())
                        .filter(AepSpringWebMvc.protect(handler, java.net.URI.create("https://service.example")))
                        .build())
                .build();

        client.perform(get("/orders"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().exists("WWW-Authenticate"));
    }

    private static AepService service() {
        InspectDocument document = InspectDocument.builder()
                .version(Aep.VERSION)
                .bindings(new InspectDocument.Bindings(List.of("http")))
                .claims(new InspectDocument.Claims(List.of(), List.of(), List.of()))
                .commands(new InspectDocument.Commands(List.of("enroll", "inspect", "status"), List.of(), Map.of()))
                .core(new InspectDocument.Core(Aep.REQUIRED_SIGNING_ALGORITHMS))
                .http(new InspectDocument.Http("/aep", null))
                .identity(new InspectDocument.Identity(List.of("did:web")))
                .service(new InspectDocument.Service("did:web:service.example"))
                .build();
        return AepService.builder(
                        document,
                        (assertion, context) -> CompletableFuture.completedFuture(new ClientAssertionClaims(
                                "did:web:agent.example",
                                "did:web:agent.example",
                                context.serviceDid(),
                                context.operation(),
                                NOW.minusSeconds(1).getEpochSecond(),
                                NOW.plusSeconds(60).getEpochSecond(),
                                assertion,
                                context.resource())))
                .clock(Clock.fixed(NOW, ZoneOffset.UTC))
                .enrollmentPolicy((request, now) -> CompletableFuture.completedFuture(
                        new EnrollmentDecision(AgentStatus.ACTIVE, false, List.of(), List.of())))
                .build();
    }
}
