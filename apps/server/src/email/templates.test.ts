import { describe, expect, it } from "vitest";
import { renderTemplate } from "./templates.js";

describe("renderTemplate", () => {
  it("substitutes every occurrence of a placeholder", () => {
    const result = renderTemplate("Code: {{code}}. Repeat: {{code}}.", { code: "123456" });
    expect(result).toBe("Code: 123456. Repeat: 123456.");
  });

  it("leaves an unknown placeholder as an empty string rather than throwing", () => {
    const result = renderTemplate("Hello {{name}}, code {{code}}", { code: "42" });
    expect(result).toBe("Hello , code 42");
  });

  it("returns content unchanged when it has no placeholders", () => {
    expect(renderTemplate("plain text", { code: "42" })).toBe("plain text");
  });
});
