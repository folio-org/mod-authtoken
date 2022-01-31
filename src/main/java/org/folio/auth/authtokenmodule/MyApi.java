package org.folio.auth.authtokenmodule;

import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.openapi.RouterBuilder;
import io.vertx.ext.web.validation.RequestParameter;
import io.vertx.ext.web.validation.RequestParameters;
import io.vertx.ext.web.validation.ValidationHandler;
import io.vertx.sqlclient.Row;
import io.vertx.sqlclient.RowIterator;
import io.vertx.sqlclient.Tuple;
import java.util.UUID;
import org.folio.okapi.common.XOkapiHeaders;
import org.folio.tlib.RouterCreator;
import org.folio.tlib.TenantInitHooks;
import org.folio.tlib.postgres.PgCqlField;
import org.folio.tlib.postgres.PgCqlQuery;
import org.folio.tlib.postgres.TenantPgPool;

public class MyApi implements RouterCreator, TenantInitHooks {
  @Override
  public Future<Router> createRouter(Vertx vertx) {
    return RouterBuilder.create(vertx, "openapi/myapi-1.0.yaml")
        .map(routerBuilder -> {
          handlers(vertx, routerBuilder);
          return routerBuilder.createRouter();
        });
  }

  private void handlers(Vertx vertx, RouterBuilder routerBuilder) {
    routerBuilder
        .operation("postTitles") // operationId in spec
        .handler(ctx -> {
          ctx.response().setStatusCode(204);
          ctx.response().end();
        });
    routerBuilder
        .operation("getTitles")
        .handler(ctx -> getTitles(vertx, ctx)
            .onFailure(cause -> {
              ctx.response().setStatusCode(500);
              ctx.response().end(cause.getMessage());
            }));
  }

  @Override
  public Future<Void> postInit(Vertx vertx, String tenant, JsonObject tenantAttributes) {
    if (!tenantAttributes.containsKey("module_to")) {
      return Future.succeededFuture(); // doing nothing for disable
    }
    TenantPgPool pool = TenantPgPool.pool(vertx, tenant);
    Future<Void> future = pool.query(
            "CREATE TABLE IF NOT EXISTS " + pool.getSchema() + ".mytable "
                + "(id UUID PRIMARY key, title text)")
        .execute().mapEmpty();
    JsonArray parameters = tenantAttributes.getJsonArray("parameters");
    if (parameters != null) {
      for (int i = 0; i < parameters.size(); i++) {
        JsonObject parameter = parameters.getJsonObject(i);
        if ("loadSample".equals(parameter.getString("key"))
            && "true".equals(parameter.getString("value"))) {
          future = future.compose(x ->
              pool.preparedQuery("INSERT INTO " + pool.getSchema() + ".mytable"
                      + "(id, title) VALUES ($1, $2)")
                  .execute(Tuple.of(UUID.randomUUID(), "First title")).mapEmpty()
          );
          future = future.compose(x ->
              pool.preparedQuery("INSERT INTO " + pool.getSchema() + ".mytable"
                      + "(id, title) VALUES ($1, $2)")
                  .execute(Tuple.of(UUID.randomUUID(), "Second title")).mapEmpty()
          );
        }
      }
    }
    return future;
  }

  private Future<Void> getTitles(Vertx vertx, RoutingContext ctx) {
    RequestParameters params = ctx.get(ValidationHandler.REQUEST_CONTEXT_KEY);
    String tenant = params.headerParameter(XOkapiHeaders.TENANT).getString();
    PgCqlQuery pgCqlQuery = PgCqlQuery.query();
    RequestParameter query = params.queryParameter("query");
    pgCqlQuery.parse(query == null ? null : query.getString());
    pgCqlQuery.addField(new PgCqlField("cql.allRecords", PgCqlField.Type.ALWAYS_MATCHES));
    pgCqlQuery.addField(new PgCqlField("id", PgCqlField.Type.UUID));
    pgCqlQuery.addField(new PgCqlField("title", PgCqlField.Type.FULLTEXT));
    TenantPgPool pool = TenantPgPool.pool(vertx, tenant);
    String sql = "SELECT * FROM " + pool.getSchema() + ".mytable";
    String where = pgCqlQuery.getWhereClause();
    if (where != null) {
      sql = sql + " WHERE " + where;
    }
    String orderBy = pgCqlQuery.getOrderByClause();
    if (orderBy != null) {
      sql = sql + " ORDER BY " + orderBy;
    }
    return pool.query(sql).execute().onSuccess(rows -> {
      RowIterator<Row> iterator = rows.iterator();
      JsonArray titles = new JsonArray();
      while (iterator.hasNext()) {
        Row row = iterator.next();
        titles.add(new JsonObject()
            .put("id", row.getUUID("id").toString())
            .put("title", row.getString("title"))
        );
      }
      ctx.response().putHeader("Content-Type", "application/json");
      ctx.response().setStatusCode(200);
      JsonObject result = new JsonObject().put("titles", titles);
      ctx.response().end(result.encode());
    }).mapEmpty();
  }

}
