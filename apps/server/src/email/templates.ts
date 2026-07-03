/**
 * Deliberately simple: `{{key}}` substitution against a flat variables map,
 * nothing more. Every drafted template (seed-data/email-templates.json) only
 * ever uses `{{code}}`; an unknown placeholder is left blank rather than
 * throwing, so a template referencing a variable a caller forgot to pass
 * degrades to an empty string instead of a 500.
 */
export function renderTemplate(content: string, variables: Record<string, string>): string {
  return content.replace(/\{\{(\w+)\}\}/g, (_match, key: string) => variables[key] ?? "");
}
