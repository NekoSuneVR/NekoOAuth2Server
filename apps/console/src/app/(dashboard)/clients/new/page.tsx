import { NewClientForm } from "./NewClientForm";

export default function NewClientPage() {
  return (
    <div>
      <h1 className="text-2xl font-semibold text-foreground">Register new client</h1>
      <p className="mt-2 text-sm text-muted">Adds a new downstream Neko* project as an OAuth2 client.</p>
      <NewClientForm />
    </div>
  );
}
