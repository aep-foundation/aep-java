# AEP Jakarta Servlet Adapter

`aep-servlet` exposes an `AepService` in a Jakarta Servlet 6 container. It maps requests and
responses without selecting a JSON library.

See the root [installation guide](../README.md#installation), then add `aep-servlet`, the Servlet
API supplied by the container, and exactly one AEP JSON provider.

Register the command Servlet at `/` so the advertised absolute AEP paths remain intact:

```java
AepServiceHttpHandler handler = new AepServiceHttpHandler(service);
servletContext.addServlet("aep", new AepServlet(handler)).addMapping("/");
```

When asynchronous Servlet processing is enabled, `AepServlet` completes command responses without
holding the request thread. Otherwise, it waits for the Service completion stage.

Protect application routes with `AepAuthenticationFilter`:

```java
AepAuthenticationFilter filter = new AepAuthenticationFilter(
    handler,
    URI.create("https://service.example"));
servletContext.addFilter("aep-authentication", filter).addMappingForUrlPatterns(
    EnumSet.of(DispatcherType.REQUEST), false, "/orders/*");
```

After successful authentication, the filter stores an `AuthenticatedPrincipal` under
`AepAuthenticationFilter.PRINCIPAL_ATTRIBUTE` and continues the filter chain. The Servlet filter
contract is synchronous, so authentication waits on the request thread.
