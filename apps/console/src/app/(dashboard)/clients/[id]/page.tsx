import { notFound } from "next/navigation";
import { AdminApiError, callAdminApi } from "@/lib/adminApi";
import type { ClientRecord } from "../actions";
import { ClientDetail } from "./ClientDetail";

export default async function ClientDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;

  let client: ClientRecord;
  try {
    client = await callAdminApi<ClientRecord>(`/api/admin/clients/${id}`);
  } catch (err) {
    if (err instanceof AdminApiError && err.status === 404) notFound();
    throw err;
  }

  return (
    <div>
      <h1 className="text-2xl font-semibold text-foreground">{client.name}</h1>
      <div className="mt-6">
        <ClientDetail client={client} />
      </div>
    </div>
  );
}
