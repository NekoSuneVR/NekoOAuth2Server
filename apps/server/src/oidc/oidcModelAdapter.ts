import type { Prisma } from "@prisma/client";
import { prisma } from "../db.js";

/**
 * Generic oidc-provider storage adapter, backed by the OidcModel table.
 * Handles every oidc-provider model EXCEPT "Client" (see clientAdapter.ts),
 * mirroring the interface oidc-provider's own memory adapter implements:
 * https://github.com/panva/node-oidc-provider/blob/main/lib/adapters/memory_adapter.js
 */
export class OidcModelAdapter {
  private readonly type: string;

  constructor(name: string) {
    this.type = name;
  }

  async upsert(id: string, payload: Record<string, unknown>, expiresIn?: number) {
    const expiresAt = expiresIn ? new Date(Date.now() + expiresIn * 1000) : null;
    const grantId = typeof payload.grantId === "string" ? payload.grantId : null;
    const userCode = typeof payload.userCode === "string" ? payload.userCode : null;
    const uid = typeof payload.uid === "string" ? payload.uid : null;

    const jsonPayload = payload as Prisma.InputJsonValue;
    await prisma.oidcModel.upsert({
      where: { type_id: { type: this.type, id } },
      create: { type: this.type, id, payload: jsonPayload, grantId, userCode, uid, expiresAt },
      update: { payload: jsonPayload, grantId, userCode, uid, expiresAt },
    });
  }

  async find(id: string) {
    const row = await prisma.oidcModel.findUnique({
      where: { type_id: { type: this.type, id } },
    });
    if (!row) return undefined;
    if (row.expiresAt && row.expiresAt.getTime() < Date.now()) return undefined;
    return row.payload as Record<string, unknown>;
  }

  async findByUserCode(userCode: string) {
    const row = await prisma.oidcModel.findUnique({
      where: { type_userCode: { type: this.type, userCode } },
    });
    if (!row) return undefined;
    if (row.expiresAt && row.expiresAt.getTime() < Date.now()) return undefined;
    return row.payload as Record<string, unknown>;
  }

  async findByUid(uid: string) {
    const row = await prisma.oidcModel.findUnique({
      where: { type_uid: { type: this.type, uid } },
    });
    if (!row) return undefined;
    if (row.expiresAt && row.expiresAt.getTime() < Date.now()) return undefined;
    return row.payload as Record<string, unknown>;
  }

  async consume(id: string) {
    const row = await prisma.oidcModel.findUnique({
      where: { type_id: { type: this.type, id } },
    });
    if (!row) return;
    const payload = {
      ...(row.payload as Record<string, unknown>),
      consumed: Math.floor(Date.now() / 1000),
    } as Prisma.InputJsonValue;
    await prisma.oidcModel.update({
      where: { type_id: { type: this.type, id } },
      data: { payload },
    });
  }

  async destroy(id: string) {
    await prisma.oidcModel.deleteMany({ where: { type: this.type, id } });
  }

  async revokeByGrantId(grantId: string) {
    await prisma.oidcModel.deleteMany({ where: { grantId } });
  }
}
