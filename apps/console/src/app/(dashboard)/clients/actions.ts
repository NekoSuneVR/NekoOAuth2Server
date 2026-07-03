"use server";

import { revalidatePath } from "next/cache";
import { callAdminApi } from "@/lib/adminApi";

export interface ClientRecord {
  id: string;
  tenantId: string;
  name: string;
  clientId: string;
  isConfidential: boolean;
  redirectUris: string[];
  grantTypes: string[];
  responseTypes: string[];
  scope: string;
  tokenEndpointAuthMethod: string;
  createdAt: string;
  updatedAt: string;
  hasSecret: boolean;
}

export interface CreateClientState {
  error?: string;
  created?: ClientRecord & { clientSecret: string | null };
}

export async function createClientAction(
  _prev: CreateClientState,
  formData: FormData,
): Promise<CreateClientState> {
  const name = String(formData.get("name") ?? "").trim();
  const redirectUris = String(formData.get("redirectUris") ?? "")
    .split("\n")
    .map((u) => u.trim())
    .filter(Boolean);
  const isConfidential = formData.get("isConfidential") === "on";

  if (!name) return { error: "Name is required." };
  if (redirectUris.length === 0) return { error: "At least one redirect URI is required." };

  try {
    const created = await callAdminApi<ClientRecord & { clientSecret: string | null }>("/api/admin/clients", {
      method: "POST",
      body: JSON.stringify({
        name,
        redirectUris,
        isConfidential,
        tokenEndpointAuthMethod: isConfidential ? "client_secret_basic" : "none",
      }),
    });
    revalidatePath("/clients");
    return { created };
  } catch (err) {
    return { error: err instanceof Error ? err.message : "Failed to create client." };
  }
}

export interface RotateSecretState {
  error?: string;
  clientSecret?: string;
}

export async function rotateSecretAction(
  clientId: string,
  _prev: RotateSecretState,
): Promise<RotateSecretState> {
  try {
    const result = await callAdminApi<ClientRecord & { clientSecret: string }>(
      `/api/admin/clients/${clientId}/rotate-secret`,
      { method: "POST" },
    );
    revalidatePath(`/clients/${clientId}`);
    return { clientSecret: result.clientSecret };
  } catch (err) {
    return { error: err instanceof Error ? err.message : "Failed to rotate secret." };
  }
}

export interface UpdateClientState {
  error?: string;
  saved?: boolean;
}

export async function updateClientAction(
  clientId: string,
  _prev: UpdateClientState,
  formData: FormData,
): Promise<UpdateClientState> {
  const name = String(formData.get("name") ?? "").trim();
  const redirectUris = String(formData.get("redirectUris") ?? "")
    .split("\n")
    .map((u) => u.trim())
    .filter(Boolean);

  if (!name) return { error: "Name is required." };
  if (redirectUris.length === 0) return { error: "At least one redirect URI is required." };

  try {
    await callAdminApi<ClientRecord>(`/api/admin/clients/${clientId}`, {
      method: "PATCH",
      body: JSON.stringify({ name, redirectUris }),
    });
    revalidatePath(`/clients/${clientId}`);
    revalidatePath("/clients");
    return { saved: true };
  } catch (err) {
    return { error: err instanceof Error ? err.message : "Failed to update client." };
  }
}
