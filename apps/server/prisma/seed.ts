import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { PrismaClient } from "@prisma/client";
import bcrypt from "bcryptjs";
import { encryptSecret } from "../src/security/encryption.js";

const prisma = new PrismaClient();

const TEST_PASSWORD = "correct-horse-battery-staple";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

interface SeedEmailTemplate {
  usageType: string;
  subject: string;
  content: string;
  contentType: string;
}

async function main() {
  const tenant = await prisma.tenant.upsert({
    where: { slug: "neko" },
    update: {},
    create: { name: "Neko", slug: "neko" },
  });

  const publicClient = await prisma.client.upsert({
    where: { clientId: "test-public-client" },
    update: {},
    create: {
      tenantId: tenant.id,
      name: "Test Public Client",
      clientId: "test-public-client",
      clientSecret: null,
      isConfidential: false,
      redirectUris: ["http://localhost:3000/callback"],
      scope: "openid profile email offline_access roles",
      tokenEndpointAuthMethod: "none",
    },
  });

  await prisma.client.upsert({
    where: { clientId: "test-confidential-client" },
    update: {},
    create: {
      tenantId: tenant.id,
      name: "Test Confidential Client",
      clientId: "test-confidential-client",
      clientSecret: encryptSecret("test-confidential-secret"),
      isConfidential: true,
      redirectUris: ["http://localhost:3000/callback"],
      tokenEndpointAuthMethod: "client_secret_basic",
    },
  });

  await prisma.client.upsert({
    where: { clientId: "test-service-client" },
    update: {},
    create: {
      tenantId: tenant.id,
      name: "Test Service Client (client_credentials)",
      clientId: "test-service-client",
      clientSecret: encryptSecret("test-service-secret"),
      isConfidential: true,
      redirectUris: [],
      grantTypes: ["client_credentials"],
      responseTypes: [],
      scope: "internal:read internal:write",
      tokenEndpointAuthMethod: "client_secret_basic",
    },
  });

  const consoleClient = await prisma.client.upsert({
    where: { clientId: "neko-console" },
    update: {},
    create: {
      tenantId: tenant.id,
      name: "Neko Admin Console",
      clientId: "neko-console",
      // Plaintext dev secret, same as test-confidential-client above — a
      // real deployment would set NEKO_CONSOLE_CLIENT_SECRET to something
      // generated, not this. The console is a server-rendered Next.js app
      // (NextAuth's OAuth exchange runs in server-side route handlers), so
      // holding a real confidential-client secret is the correct choice,
      // unlike a browser-only SPA.
      clientSecret: encryptSecret("neko-console-dev-secret"),
      isConfidential: true,
      redirectUris: ["http://localhost:3001/api/auth/callback/neko"],
      scope: "openid profile email roles",
      tokenEndpointAuthMethod: "client_secret_basic",
    },
  });

  const user = await prisma.user.upsert({
    where: { primaryEmail: "test@example.com" },
    update: {},
    create: {
      primaryEmail: "test@example.com",
      emailVerified: true,
      displayName: "Test User",
      passwordHash: await bcrypt.hash(TEST_PASSWORD, 10),
    },
  });

  const adminRole = await prisma.role.upsert({
    where: { clientId_name: { clientId: publicClient.id, name: "admin" } },
    update: {},
    create: {
      clientId: publicClient.id,
      name: "admin",
      description: "Demo role for manual RBAC testing — grants admin:access on test-public-client only.",
      permissions: ["admin:access", "email:manage_templates", "email:manage_smtp"],
    },
  });

  await prisma.userRole.upsert({
    where: { userId_roleId: { userId: user.id, roleId: adminRole.id } },
    update: {},
    create: { userId: user.id, roleId: adminRole.id },
  });

  const consoleAdminRole = await prisma.role.upsert({
    where: { clientId_name: { clientId: consoleClient.id, name: "console-admin" } },
    update: {},
    create: {
      clientId: consoleClient.id,
      name: "console-admin",
      description: "Grants access to apps/console's admin screens (Phase 8/9).",
      permissions: [
        "admin:manage_clients",
        "admin:manage_users",
        "admin:manage_webhooks",
        "admin:manage_connectors",
        "admin:view_audit_log",
        "email:manage_templates",
        "email:manage_smtp",
      ],
    },
  });

  await prisma.userRole.upsert({
    where: { userId_roleId: { userId: user.id, roleId: consoleAdminRole.id } },
    update: {},
    create: { userId: user.id, roleId: consoleAdminRole.id },
  });

  const templatesPath = path.join(__dirname, "..", "seed-data", "email-templates.json");
  const templates = JSON.parse(readFileSync(templatesPath, "utf-8")) as SeedEmailTemplate[];
  for (const template of templates) {
    await prisma.emailTemplate.upsert({
      where: { usageType: template.usageType },
      update: {},
      create: template,
    });
  }
}

main()
  .then(() => prisma.$disconnect())
  .catch(async (err) => {
    console.error(err);
    await prisma.$disconnect();
    process.exit(1);
  });
