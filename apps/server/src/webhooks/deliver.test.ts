import crypto from "node:crypto";
import http, { type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { prisma } from "../db.js";
import { deliverToEndpoint } from "./deliver.js";

const SECRET = "test-webhook-secret";

describe("deliverToEndpoint", () => {
  let server: Server;
  let baseUrl: string;
  let receivedRequests: { body: string; signature: string | undefined }[];
  let failFirstNRequests: number;
  let endpointId: string;

  beforeAll(async () => {
    const tenant = await prisma.tenant.upsert({
      where: { slug: "deliver-test-tenant" },
      update: {},
      create: { name: "Deliver Test Tenant", slug: "deliver-test-tenant" },
    });
    const client = await prisma.client.upsert({
      where: { clientId: "deliver-test-client" },
      update: {},
      create: {
        tenantId: tenant.id,
        name: "Deliver Test Client",
        clientId: "deliver-test-client",
        clientSecret: null,
        isConfidential: false,
        redirectUris: ["http://localhost:3000/callback"],
      },
    });

    server = http.createServer((req, res) => {
      let body = "";
      req.on("data", (chunk) => (body += chunk));
      req.on("end", () => {
        receivedRequests.push({ body, signature: req.headers["x-neko-signature"] as string | undefined });
        if (receivedRequests.length <= failFirstNRequests) {
          res.writeHead(500).end("fail");
        } else {
          res.writeHead(200).end("ok");
        }
      });
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const { port } = server.address() as AddressInfo;
    baseUrl = `http://127.0.0.1:${port}`;

    const endpoint = await prisma.webhookEndpoint.create({
      data: { clientId: client.id, url: `${baseUrl}/webhook`, secret: SECRET },
    });
    endpointId = endpoint.id;
  });

  beforeEach(() => {
    receivedRequests = [];
    failFirstNRequests = 0;
  });

  afterEach(async () => {
    await prisma.webhookDelivery.deleteMany({ where: { webhookEndpointId: endpointId } });
  });

  it("succeeds on the first attempt with a correctly signed payload, logging one delivery row", async () => {
    await deliverToEndpoint({ id: endpointId, url: `${baseUrl}/webhook`, secret: SECRET }, "user.deleted", { sub: "user-1" });

    expect(receivedRequests).toHaveLength(1);
    const expectedSig = `sha256=${crypto.createHmac("sha256", SECRET).update(receivedRequests[0].body).digest("hex")}`;
    expect(receivedRequests[0].signature).toBe(expectedSig);

    const deliveries = await prisma.webhookDelivery.findMany({ where: { webhookEndpointId: endpointId } });
    expect(deliveries).toHaveLength(1);
    expect(deliveries[0].attempt).toBe(1);
    expect(deliveries[0].statusCode).toBe(200);
    expect(deliveries[0].error).toBeNull();
    expect(deliveries[0].payload).toMatchObject({ event: "user.deleted", data: { sub: "user-1" } });
  });

  it("retries with backoff after a failure and succeeds on a later attempt", async () => {
    failFirstNRequests = 1;

    await deliverToEndpoint({ id: endpointId, url: `${baseUrl}/webhook`, secret: SECRET }, "user.deleted", { sub: "user-2" });

    expect(receivedRequests).toHaveLength(2);

    const deliveries = await prisma.webhookDelivery.findMany({
      where: { webhookEndpointId: endpointId },
      orderBy: { attempt: "asc" },
    });
    expect(deliveries).toHaveLength(2);
    expect(deliveries[0].attempt).toBe(1);
    expect(deliveries[0].statusCode).toBe(500);
    expect(deliveries[0].error).toContain("non-2xx");
    expect(deliveries[1].attempt).toBe(2);
    expect(deliveries[1].statusCode).toBe(200);
    expect(deliveries[1].error).toBeNull();
  });

  it("gives up after 3 attempts against a permanently failing endpoint, logging every attempt", async () => {
    failFirstNRequests = 999;

    await deliverToEndpoint({ id: endpointId, url: `${baseUrl}/webhook`, secret: SECRET }, "user.deleted", { sub: "user-3" });

    expect(receivedRequests).toHaveLength(3);

    const deliveries = await prisma.webhookDelivery.findMany({
      where: { webhookEndpointId: endpointId },
      orderBy: { attempt: "asc" },
    });
    expect(deliveries).toHaveLength(3);
    expect(deliveries.every((d) => d.statusCode === 500)).toBe(true);
    expect(deliveries.map((d) => d.attempt)).toEqual([1, 2, 3]);
  }, 15000);

  it("blocks delivery to a private/internal URL instead of ever making the request", async () => {
    await deliverToEndpoint({ id: endpointId, url: "http://169.254.169.254/latest/meta-data", secret: SECRET }, "user.deleted", {
      sub: "user-4",
    });

    expect(receivedRequests).toHaveLength(0);
    const deliveries = await prisma.webhookDelivery.findMany({ where: { webhookEndpointId: endpointId } });
    expect(deliveries.every((d) => d.error?.includes("blocked by SSRF guard"))).toBe(true);
  }, 15000);
});
