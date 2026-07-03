import { PrismaClient } from "@prisma/client";
import bcrypt from "bcryptjs";

const prisma = new PrismaClient();

const TEST_PASSWORD = "correct-horse-battery-staple";

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
      clientSecret: "test-confidential-secret",
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
      clientSecret: "test-service-secret",
      isConfidential: true,
      redirectUris: [],
      grantTypes: ["client_credentials"],
      responseTypes: [],
      scope: "internal:read internal:write",
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
      permissions: ["admin:access"],
    },
  });

  await prisma.userRole.upsert({
    where: { userId_roleId: { userId: user.id, roleId: adminRole.id } },
    update: {},
    create: { userId: user.id, roleId: adminRole.id },
  });
}

main()
  .then(() => prisma.$disconnect())
  .catch(async (err) => {
    console.error(err);
    await prisma.$disconnect();
    process.exit(1);
  });
