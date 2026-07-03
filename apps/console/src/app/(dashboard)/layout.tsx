import Link from "next/link";
import { redirect } from "next/navigation";
import { auth, signOut } from "@/auth";

export default async function DashboardLayout({ children }: { children: React.ReactNode }) {
  const session = await auth();
  if (!session?.user) {
    redirect("/login");
  }
  if (!session.permissions.includes("admin:manage_clients")) {
    redirect("/forbidden");
  }

  return (
    <div className="flex min-h-full flex-1 flex-col">
      <header className="border-b border-border">
        <div className="mx-auto flex max-w-5xl items-center justify-between px-6 py-4">
          <Link href="/clients" className="font-semibold text-foreground">
            Neko<span className="text-accent">OAuth2Server</span> Console
          </Link>
          <nav className="flex items-center gap-6 text-sm text-muted">
            <Link href="/clients" className="hover:text-foreground">
              Clients
            </Link>
            <span className="text-foreground">{session.user.name ?? session.user.email}</span>
            <form
              action={async () => {
                "use server";
                await signOut({ redirectTo: "/login" });
              }}
            >
              <button type="submit" className="hover:text-foreground">
                Sign out
              </button>
            </form>
          </nav>
        </div>
      </header>
      <main className="mx-auto w-full max-w-5xl flex-1 px-6 py-10">{children}</main>
    </div>
  );
}
