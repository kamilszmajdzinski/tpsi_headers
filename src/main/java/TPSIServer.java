import com.cedarsoftware.util.io.JsonWriter;
import com.sun.net.httpserver.*;
//import jdk.nashorn.internal.ir.debug.JSONWriter;

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
        int port = 8080;
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/", new RootHandler());
        server.createContext("/echo/", new EchoHandler());
        server.createContext("/redirect/", new RedirectHandler());
        server.createContext("/cookies/", new CookiesHandler());
        server.createContext("/auth/", new AuthHandler());

        HttpContext authContext = server.createContext("/auth2/", new Auth2Handler());
        authContext.setAuthenticator(new BasicAuthenticator("get") {
            @Override
            public boolean checkCredentials(String username, String password) {
                return username.equals("user") && password.equals("pass");
            }
        });

        System.out.println("Starting server on port: " + port);
        server.start();
    }

    static class RootHandler implements HttpHandler {
        public void handle(HttpExchange exchange) throws IOException {
            standardResponse(exchange);
        }

        public static void standardResponse(HttpExchange exchange) throws IOException{
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
        public void handle(HttpExchange exchange) throws IOException{
            String user = "user", pass = "password";

            List<String> authorization;

            if(exchange.getRequestHeaders().containsKey("Authorization")) {
                authorization = exchange.getRequestHeaders().get("Authorization");
                byte[] credentials = Base64.getDecoder().decode(authorization.get(0).split(" ")[1].getBytes());
                String[] stringCredentials = new String(credentials).split(":");
                String reqUser = stringCredentials[0], reqPass = stringCredentials[1];

                if ((reqUser.equals(user))&&(reqPass.equals(pass))){
                    RootHandler.standardResponse(exchange);
                } else {
                    unauthorizedResponse(exchange);
                }
            }else unauthorizedResponse(exchange);
        }

        public void unauthorizedResponse(HttpExchange exchange) throws IOException{
            exchange.getResponseHeaders().set("WWW-Authenticate", "Basic");
            String mess = " You shall not pass!";
            exchange.sendResponseHeaders(401, mess.length());
            OutputStream os = exchange.getResponseBody();
            os.write(mess.getBytes());
            os.close();
        }
    }

    static class Auth2Handler implements HttpHandler {
        public void handle(HttpExchange exchange) throws IOException{
            RootHandler.standardResponse(exchange);
        }
    }

}


