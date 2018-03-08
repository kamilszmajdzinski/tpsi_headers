import com.cedarsoftware.util.io.JsonWriter;
import com.sun.net.httpserver.*;
import jdk.nashorn.internal.ir.debug.JSONWriter;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

public class TPSIServer {
    public static void main(String[] args) throws Exception {
        int port = 8000;
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/", new RootHandler());
        server.createContext("/echo/", new EchoHandler());
        server.createContext("/redirect/", new RedirectHandler());
        server.createContext("/cookies/", new CookiesHandler());
        server.createContext("/auth/", new AuthHandler());


        System.out.println("Starting server on port: " + port);
        server.start();
    }

    static class RootHandler implements HttpHandler {
        public void handle(HttpExchange exchange) throws IOException {
            byte[] response = Files.readAllBytes(Paths.get("index.html"));
            exchange.getResponseHeaders().set("Content-Type", "text/html");
            exchange.sendResponseHeaders(200, response.length);
            OutputStream os = exchange.getResponseBody();
            os.write(response);
            os.close();
        }
    }

    static class EchoHandler implements HttpHandler {
        public void handle(HttpExchange exchange) throws IOException {

            Headers headers = exchange.getRequestHeaders();
            String json = JsonWriter.objectToJson(headers);
            String.format(json = JsonWriter.formatJson(json));

            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, json.length());
            OutputStream os = exchange.getResponseBody();
            os.write(json.getBytes());
            os.close();
        }
    }


    static class RedirectHandler implements HttpHandler {
        public void handle(HttpExchange exchange) throws IOException {


            exchange.getResponseHeaders().set("Location", "http://google.pl");
            exchange.sendResponseHeaders(301, 0);
            OutputStream os = exchange.getResponseBody();
            os.write(null);
            os.close();
        }
    }


    static class CookiesHandler implements HttpHandler {
        public void handle(HttpExchange exchange) throws IOException {
            UUID idRnd = UUID.randomUUID();
            String id = String.valueOf(idRnd);

            byte[] response = Files.readAllBytes(Paths.get("index.html"));
            exchange.getResponseHeaders().set("Content-Type", "text/html");
            exchange.getResponseHeaders().set("Set-Cookie", "ID=" + id);

            exchange.sendResponseHeaders(200, response.length);
            OutputStream os = exchange.getResponseBody();
            os.write(response);
            os.close();
            System.out.println(id);
        }
    }


    static class AuthHandler implements HttpHandler {
        public void handle(HttpExchange exchange) throws IOException {
            byte[] response = Files.readAllBytes(Paths.get("index.html"));
            List<String> authHeader = null;
            if (exchange.getRequestHeaders().containsKey("Authorization")) {
                authHeader = exchange.getRequestHeaders().get("Authorization");
                byte[] decodedCredentials = Base64.getDecoder().decode(authHeader.get(1));
                String[] stringCredentials = decodedCredentials.toString().split("\\:");
                String requestUser = stringCredentials[0];
                String requestPassword = stringCredentials[1];

                if (requestUser == "kamil" && requestPassword == "password") {
                    exchange.sendResponseHeaders(200, response.length);
                    OutputStream os = exchange.getResponseBody();
                    os.write(response);
                    os.close();
                } else {
                    exchange.sendResponseHeaders(401, 0);
                }

            } else {
                exchange.sendResponseHeaders(401, 0);
            }


            OutputStream os = exchange.getResponseBody();
            os.write(null);
            os.close();
        }
    }

}