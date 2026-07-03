"use client";

import Link from "next/link";
import { useActionState } from "react";
import { createClientAction, type CreateClientState } from "../actions";

const initialState: CreateClientState = {};

export function NewClientForm() {
  const [state, formAction, pending] = useActionState(createClientAction, initialState);

  if (state.created) {
    return (
      <div className="glass-card accent-glow mt-6 rounded-2xl p-6">
        <h2 className="text-lg font-semibold text-foreground">{state.created.name} registered</h2>
        <dl className="mt-4 space-y-2 text-sm">
          <div className="flex justify-between gap-4">
            <dt className="text-muted">Client ID</dt>
            <dd className="font-mono text-foreground">{state.created.clientId}</dd>
          </div>
          {state.created.clientSecret && (
            <div className="flex justify-between gap-4">
              <dt className="text-muted">Client secret</dt>
              <dd className="font-mono text-accent">{state.created.clientSecret}</dd>
            </div>
          )}
        </dl>
        {state.created.clientSecret && (
          <p className="mt-4 text-sm text-danger">
            This secret is shown once. Copy it now — it can&apos;t be retrieved again, only rotated.
          </p>
        )}
        <Link href={`/clients/${state.created.id}`} className="mt-6 inline-block text-sm text-accent hover:underline">
          Go to client →
        </Link>
      </div>
    );
  }

  return (
    <form action={formAction} className="glass-card mt-6 space-y-4 rounded-2xl p-6">
      {state.error && <p className="rounded bg-accent-soft px-3 py-2 text-sm text-danger">{state.error}</p>}

      <div>
        <label htmlFor="name" className="block text-sm text-muted">
          Name
        </label>
        <input
          id="name"
          name="name"
          required
          className="mt-1 w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground outline-none focus:border-accent"
          placeholder="e.g. NekosMediaPlayer"
        />
      </div>

      <div>
        <label htmlFor="redirectUris" className="block text-sm text-muted">
          Redirect URIs (one per line)
        </label>
        <textarea
          id="redirectUris"
          name="redirectUris"
          required
          rows={3}
          className="mt-1 w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground outline-none focus:border-accent"
          placeholder="https://example.com/auth/callback"
        />
      </div>

      <label className="flex items-center gap-2 text-sm text-foreground">
        <input type="checkbox" name="isConfidential" defaultChecked className="accent-[var(--color-accent)]" />
        Confidential client (server-side app — issues a client secret)
      </label>

      <button
        type="submit"
        disabled={pending}
        className="rounded-xl bg-accent px-6 py-3 font-medium text-black transition hover:bg-accent-strong disabled:opacity-50"
      >
        {pending ? "Registering…" : "Register client"}
      </button>
    </form>
  );
}
