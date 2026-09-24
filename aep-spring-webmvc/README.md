# AEP Spring Web MVC Adapter

`aep-spring-webmvc` exposes an `AepService` through Spring Web MVC functional routes. One artifact
supports Spring Framework 6 and 7.

See the root [installation guide](../README.md#installation), then add `aep-spring-webmvc` and
exactly one JSON provider:

- Spring Framework 6 applications normally select `aep-json-jackson2`.
- Spring Framework 7 applications normally select `aep-json-jackson3`.

Spring Framework 6 runs on the Jakarta Servlet 6.0 generation. Spring Framework 7 requires
Jakarta Servlet 6.1. The application server and Spring dependency management remain responsible
for that Servlet version; the AEP adapter declares the Servlet API as provided.

The adapter reads and writes raw bytes and delegates AEP JSON to `AepJson`; it does not use
Spring's configured Jackson message converter.

Expose the advertised AEP commands as a router bean:

```java
@Bean
RouterFunction<ServerResponse> aepRoutes(AepService service) {
    return AepSpringWebMvc.routes(new AepServiceHttpHandler(service));
}
```

Protect another functional route:

```java
RouterFunction<ServerResponse> orders = RouterFunctions.route()
    .GET("/orders/{id}", this::getOrder)
    .filter(AepSpringWebMvc.protect(
        handler,
        URI.create("https://service.example")))
    .build();
```

After successful authentication, the filter stores an `AuthenticatedPrincipal` under
`AepSpringWebMvc.PRINCIPAL_ATTRIBUTE` in the `ServerRequest` attributes.

The authentication filter waits on the request thread, including when an asynchronous store
or verifier is used. This keeps the application handler on the thread where Spring and the
application established their request context. A request thread remains occupied until
authentication completes; the application handler can still return an asynchronous response.
AEP command routes complete their responses asynchronously.

Applications that need nonblocking authentication can build their own integration around
`AepServiceHttpHandler.authenticate()`, which returns a `CompletionStage`. That integration
must manage Spring's request context and dispatch lifecycle; moving the filter to an executor
does not preserve the request thread's context.
