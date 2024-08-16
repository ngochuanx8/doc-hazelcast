import io.vertx.core.AbstractVerticle;
import io.vertx.core.Vertx;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.handler.BodyHandler;
import io.vertx.ext.web.RoutingContext;
import org.owasp.html.PolicyFactory;
import org.owasp.html.Sanitizers;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class OwaspJsonSanitizerExample extends AbstractVerticle {

  private final PolicyFactory policy = Sanitizers.FORMATTING.and(Sanitizers.BLOCKS);
  private final ObjectMapper objectMapper = new ObjectMapper();

  @Override
  public void start() {
    Router router = Router.router(vertx);

    router.route().handler(BodyHandler.create());

    router.post("/data").handler(this::sanitizeJsonRequestBody).handler(ctx -> {
      ctx.response().end("Request processed successfully!");
    });

    vertx.createHttpServer().requestHandler(router).listen(8080);
  }

  private void sanitizeJsonRequestBody(RoutingContext ctx) {
    try {
      JsonNode jsonNode = objectMapper.readTree(ctx.getBodyAsString());

      // Sanitize all string fields in the JSON object
      jsonNode.fields().forEachRemaining(entry -> {
        if (entry.getValue().isTextual()) {
          String sanitizedValue = policy.sanitize(entry.getValue().asText());
          ((ObjectNode) jsonNode).put(entry.getKey(), sanitizedValue);
        }
      });

      // If sanitized values are different from the original, block the request
      if (!jsonNode.toString().equals(ctx.getBodyAsString())) {
        ctx.response().setStatusCode(400).end("Request contains forbidden content!");
      } else {
        ctx.next();
      }
    } catch (Exception e) {
      ctx.response().setStatusCode(400).end("Invalid JSON body!");
    }
  }

  public static void main(String[] args) {
    Vertx vertx = Vertx.vertx();
    vertx.deployVerticle(new OwaspJsonSanitizerExample());
  }
}
