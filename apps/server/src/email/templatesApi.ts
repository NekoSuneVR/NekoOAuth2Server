import { Router } from "express";
import { prisma } from "../db.js";
import { requirePermission } from "../rbac/requirePermission.js";
import { renderTemplate } from "./templates.js";
import { EMAIL_USAGE_TYPES, isEmailUsageType } from "./types.js";

/**
 * The backend half of Phase 6's "admin console screen: edit subject + HTML
 * per usageType, with a live preview" — there's no console UI yet (Phase 8
 * hasn't started, same gap Phase 3 called out for the RBAC admin API), so
 * this is the real, permission-gated API a future console screen calls.
 */
export const emailTemplatesRouter = Router();
emailTemplatesRouter.use(requirePermission("email:manage_templates"));

emailTemplatesRouter.get("/", async (_req, res) => {
  const templates = await prisma.emailTemplate.findMany({ orderBy: { usageType: "asc" } });
  res.json(templates);
});

emailTemplatesRouter.get("/:usageType", async (req, res) => {
  const { usageType } = req.params;
  if (!isEmailUsageType(usageType)) {
    res.status(400).json({ error: "invalid_usage_type", allowed: EMAIL_USAGE_TYPES });
    return;
  }

  const template = await prisma.emailTemplate.findUnique({ where: { usageType } });
  if (!template) {
    res.status(404).json({ error: "not_found" });
    return;
  }
  res.json(template);
});

emailTemplatesRouter.put("/:usageType", async (req, res) => {
  const { usageType } = req.params;
  if (!isEmailUsageType(usageType)) {
    res.status(400).json({ error: "invalid_usage_type", allowed: EMAIL_USAGE_TYPES });
    return;
  }

  const body = req.body as { subject?: unknown; content?: unknown; contentType?: unknown };
  if (typeof body.subject !== "string" || typeof body.content !== "string") {
    res.status(400).json({ error: "invalid_body", error_description: "subject and content are required strings" });
    return;
  }

  const contentType = typeof body.contentType === "string" ? body.contentType : undefined;
  const template = await prisma.emailTemplate.upsert({
    where: { usageType },
    update: { subject: body.subject, content: body.content, contentType },
    create: { usageType, subject: body.subject, content: body.content, contentType: contentType ?? "text/html" },
  });
  res.json(template);
});

/**
 * Renders subject/html for review before saving. Accepts unsaved
 * subject/content in the body (the "live preview while editing" case) and
 * falls back to the currently-stored template when either is omitted (the
 * "preview what's already saved" case).
 */
emailTemplatesRouter.post("/:usageType/preview", async (req, res) => {
  const { usageType } = req.params;
  if (!isEmailUsageType(usageType)) {
    res.status(400).json({ error: "invalid_usage_type", allowed: EMAIL_USAGE_TYPES });
    return;
  }

  const body = req.body as { subject?: unknown; content?: unknown; variables?: unknown };
  let subjectSource = typeof body.subject === "string" ? body.subject : undefined;
  let contentSource = typeof body.content === "string" ? body.content : undefined;

  if (subjectSource === undefined || contentSource === undefined) {
    const stored = await prisma.emailTemplate.findUnique({ where: { usageType } });
    if (!stored) {
      res.status(404).json({ error: "not_found" });
      return;
    }
    subjectSource ??= stored.subject;
    contentSource ??= stored.content;
  }

  const variables =
    typeof body.variables === "object" && body.variables !== null ? (body.variables as Record<string, string>) : {};
  res.json({ subject: renderTemplate(subjectSource, variables), html: renderTemplate(contentSource, variables) });
});
