# AEP JDK HTTP Server Adapter

`aep-httpserver` exposes an `AepService` through the JDK `HttpServer` included with Java 17 and
newer. It is suitable for small standalone Services and examples without a web framework.

See the root [installation guide](../README.md#installation), then add `aep-httpserver` and exactly
one AEP JSON provider.

```java
HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 8080), 0);
AepServiceHttpHandler handler = new AepServiceHttpHandler(service);
AepHttpServer.register(server, handler);
server.start();
```

`register` installs every command route advertised by the Service Inspect document, including
`/.well-known/aep`.

Protect an application endpoint with the same Service:

```java
HttpHandler protectedHandler = AepHttpServer.protect(
    handler,
    URI.create("https://service.example"),
    exchange -> {
        AuthenticatedPrincipal principal = (AuthenticatedPrincipal) exchange.getAttribute(
            AepHttpServer.PRINCIPAL_ATTRIBUTE);
        byte[] response = principal.agentDid().getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(200, response.length);
        exchange.getResponseBody().write(response);
        exchange.close();
    });

server.createContext("/orders", protectedHandler);
```

The JDK server API is synchronous. AEP command and authentication stages are awaited on the
server's configured executor, so production applications should configure an executor appropriate
for their concurrency and latency requirements.
