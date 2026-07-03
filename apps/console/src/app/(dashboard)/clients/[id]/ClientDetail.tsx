"use client";

import { useActionState } from "react";
import {
  rotateSecretAction,
  updateClientAction,
  type ClientRecord,
  type RotateSecretState,
  type UpdateClientState,
} from "../actions";

const initialUpdateState: UpdateClientState = {};
const initialRotateState: RotateSecretState = {};

export function ClientDetail({ client }: { client: ClientRecord }) {
  const boundUpdate = updateClientAction.bind(null, client.id);
  const boundRotate = rotateSecretAction.bind(null, client.id);
  const [updateState, updateFormAction, updatePending] = useActionState(boundUpdate, initialUpdateState);
  const [rotateState, rotateFormAction, rotatePending] = useActionState(boundRotate, initialRotateState);

  return (
    <div className="space-y-6">
      <div className="glass-card rounded-2xl p-6">
        <dl className="space-y-2 text-sm">
          <div className="flex justify-between gap-4">
            <dt className="text-muted">Client ID</dt>
            <dd className="font-mono text-foreground">{client.clientId}</dd>
          </div>
          <div className="flex justify-between gap-4">
            <dt className="text-muted">Type</dt>
            <dd>
              <span className="inline-block rounded-full border border-border bg-accent-soft px-4 py-1 text-accent">
                {client.isConfidential ? "confidential" : "public"}
              </span>
            </dd>
          </div>
          <div className="flex justify-between gap-4">
            <dt className="text-muted">Token endpoint auth method</dt>
            <dd className="text-foreground">{client.tokenEndpointAuthMethod}</dd>
          </div>
          <div className="flex justify-between gap-4">
            <dt className="text-muted">Scope</dt>
            <dd className="font-mono text-foreground">{client.scope}</dd>
          </div>
        </dl>
      </div>

      <form action={updateFormAction} className="glass-card space-y-4 rounded-2xl p-6">
        <h2 className="text-lg font-semibold text-foreground">Edit</h2>
        {updateState.error && <p className="rounded bg-accent-soft px-3 py-2 text-sm text-danger">{updateState.error}</p>}
        {updateState.saved && <p className="text-sm text-accent">Saved.</p>}

        <div>
          <label htmlFor="name" className="block text-sm text-muted">
            Name
          </label>
          <input
            id="name"
            name="name"
            defaultValue={client.name}
            required
            className="mt-1 w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground outline-none focus:border-accent"
          />
        </div>

        <div>
          <label htmlFor="redirectUris" className="block text-sm text-muted">
            Redirect URIs (one per line)
          </label>
          <textarea
            id="redirectUris"
            name="redirectUris"
            defaultValue={client.redirectUris.join("\n")}
            required
            rows={3}
            className="mt-1 w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground outline-none focus:border-accent"
          />
        </div>

        <button
          type="submit"
          disabled={updatePending}
          className="rounded-xl bg-accent px-6 py-3 font-medium text-black transition hover:bg-accent-strong disabled:opacity-50"
        >
          {updatePending ? "Saving…" : "Save changes"}
        </button>
      </form>

      {client.isConfidential && client.tokenEndpointAuthMethod !== "none" && (
        <div className="glass-card rounded-2xl p-6">
          <h2 className="text-lg font-semibold text-foreground">Client secret</h2>
          <p className="mt-1 text-sm text-muted">
            The secret is never shown again after creation or rotation — only whether one is set.
          </p>
          {rotateState.error && <p className="mt-3 rounded bg-accent-soft px-3 py-2 text-sm text-danger">{rotateState.error}</p>}
          {rotateState.clientSecret ? (
            <div className="mt-4">
              <p className="font-mono text-sm text-accent">{rotateState.clientSecret}</p>
              <p className="mt-2 text-sm text-danger">Copy it now — this is the only time it will be shown.</p>
            </div>
          ) : (
            <form action={rotateFormAction} className="mt-4">
              <button
                type="submit"
                disabled={rotatePending}
                className="rounded-xl border border-border px-6 py-3 font-medium text-foreground transition hover:border-accent disabled:opacity-50"
              >
                {rotatePending ? "Rotating…" : "Rotate secret"}
              </button>
            </form>
          )}
        </div>
      )}
    </div>
  );
}
