import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

async function main() {
  const tenant = await prisma.tenant.upsert({
    where: { slug: "neko" },
    update: {},
    create: { name: "Neko", slug: "neko" },
  });

  await prisma.client.upsert({
    where: { clientId: "test-public-client" },
    update: {},
    create: {
      tenantId: tenant.id,
      name: "Test Public Client",
      clientId: "test-public-client",
      clientSecret: null,
      isConfidential: false,
      redirectUris: ["http://localhost:3000/callback"],
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
}

main()
  .then(() => prisma.$disconnect())
  .catch(async (err) => {
    console.error(err);
    await prisma.$disconnect();
    process.exit(1);
  });
