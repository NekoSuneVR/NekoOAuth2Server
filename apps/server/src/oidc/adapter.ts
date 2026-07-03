import { ClientAdapter } from "./clientAdapter.js";
import { OidcModelAdapter } from "./oidcModelAdapter.js";

export function adapterFactory(name: string) {
  if (name === "Client") return new ClientAdapter();
  return new OidcModelAdapter(name);
}
