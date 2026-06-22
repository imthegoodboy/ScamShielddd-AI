import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "..", "..");

function read(path) {
  return readFileSync(resolve(root, path), "utf8");
}

describe("ScamShield Anna app static contract", () => {
  it("declares required Anna grants and bundled analyzer", () => {
    const manifest = JSON.parse(read("manifest.json"));
    expect(manifest.schema).toBe(2);
    expect(manifest.required_executas[0].tool_id).toBe("bundled:scamshield-analyzer");
    expect(manifest.ui.host_api.tools).toContain("required:bundled:scamshield-analyzer");
    expect(manifest.ui.host_api.llm).toContain("complete");
    expect(manifest.ui.host_api.storage).toEqual(expect.arrayContaining(["get", "set"]));
  });

  it("keeps CSP-friendly bundle shape", () => {
    const html = read("bundle/index.html");
    expect(html).toContain('script src="app.js" type="module"');
    expect(html).not.toMatch(/<script(?![^>]+src=)/i);
    expect(html).not.toMatch(/\sstyle="/i);
  });

  it("uses Hallmark tokens instead of one-off color declarations in app CSS", () => {
    const css = read("bundle/style.css");
    expect(css).toContain("Hallmark · genre: modern-minimal");
    expect(css).toContain("@import url(\"./tokens.css\")");
    expect(css).not.toMatch(/#[0-9a-fA-F]{3,8}/);
    expect(css).not.toMatch(/transition:\s*all/);
  });

  it("keeps Anna LLM responses useful when provider text is empty", () => {
    const js = read("bundle/app.js");
    expect(js).toContain("function extractLlmText");
    expect(js).toContain("function fallbackAgentNote");
    expect(js).not.toContain("Anna returned an empty note.");
  });

  it("declares Windows binary distribution support", () => {
    const executa = JSON.parse(read("executas/scamshield-analyzer/executa.json"));
    const urls = executa.distribution.profiles.binary.binary_urls;
    expect(urls["windows-x86_64"]).toMatchObject({
      format: "zip",
      entrypoint: "tool-test-scamshield-analyzer-12345678.exe",
    });
    expect(urls["windows-x86_64"].url).toContain("windows-x86_64.zip");

    const workflow = read(".github/workflows/build-release.yml");
    expect(workflow).toContain("windows-latest");
    expect(workflow).toContain("windows-x86_64");
  });

  it("keeps chat and PDF exports evidence-complete", () => {
    const js = read("bundle/app.js");
    expect(js).toContain("function chatPromptFromReport");
    expect(js).toContain("Findings:");
    expect(js).toContain("Recommended actions:");
    expect(js).toContain("Limitations:");
    expect(js).toContain("function chunkLines");
    expect(js).not.toContain("slice(0, 58)");
  });
});
