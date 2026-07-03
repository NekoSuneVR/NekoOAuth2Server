import Link from "next/link";
import { callAdminApi } from "@/lib/adminApi";
import type { ClientRecord } from "./actions";

export default async function ClientsPage() {
  const clients = await callAdminApi<ClientRecord[]>("/api/admin/clients");

  return (
    <div>
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold text-foreground">Clients</h1>
        <Link
          href="/clients/new"
          className="rounded-xl bg-accent px-4 py-2 text-sm font-medium text-black transition hover:bg-accent-strong"
        >
          Register new client
        </Link>
      </div>

      {clients.length === 0 ? (
        <p className="mt-8 text-sm text-muted">No clients registered yet.</p>
      ) : (
        <div className="glass-card mt-6 divide-y divide-border rounded-2xl">
          {clients.map((client) => (
            <Link
              key={client.id}
              href={`/clients/${client.id}`}
              className="flex items-center justify-between px-6 py-4 transition hover:bg-background-elevated"
            >
              <div>
                <p className="font-medium text-foreground">{client.name}</p>
                <p className="text-sm text-muted">{client.clientId}</p>
              </div>
              <div className="flex items-center gap-3">
                <span className="inline-block rounded-full border border-border bg-accent-soft px-4 py-1 text-sm text-accent">
                  {client.isConfidential ? "confidential" : "public"}
                </span>
                <span className="text-sm text-muted">{client.redirectUris.length} redirect URI(s)</span>
              </div>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}
