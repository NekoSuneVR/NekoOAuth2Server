export default function ForbiddenPage() {
  return (
    <div className="flex flex-1 items-center justify-center px-6">
      <div className="glass-card w-full max-w-md rounded-2xl p-8 text-center">
        <h1 className="text-xl font-semibold text-foreground">Access denied</h1>
        <p className="mt-2 text-sm text-muted">
          Your account is signed in, but doesn&apos;t have an admin role on the console. Ask an existing admin to
          grant you the <code className="text-accent">admin:manage_clients</code> permission.
        </p>
      </div>
    </div>
  );
}
