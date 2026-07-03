import { redirect } from "next/navigation";
import { auth, signIn } from "@/auth";

export default async function LoginPage() {
  const session = await auth();
  if (session?.user) {
    redirect("/clients");
  }

  return (
    <div className="flex flex-1 items-center justify-center px-6">
      <div className="glass-card accent-glow w-full max-w-md rounded-2xl p-8 text-center">
        <h1 className="text-2xl font-semibold text-foreground">
          Neko<span className="text-accent">OAuth2Server</span> Console
        </h1>
        <p className="mt-2 text-sm text-muted">Sign in with your NekoOAuth2Server account to manage clients.</p>
        <form
          className="mt-6"
          action={async () => {
            "use server";
            await signIn("neko", { redirectTo: "/clients" });
          }}
        >
          <button
            type="submit"
            className="w-full rounded-xl bg-accent px-6 py-3 font-medium text-black transition hover:bg-accent-strong"
          >
            Sign in with NekoOAuth2Server
          </button>
        </form>
      </div>
    </div>
  );
}
