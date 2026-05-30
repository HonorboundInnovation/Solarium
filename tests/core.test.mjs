import test from "node:test";
import assert from "node:assert/strict";

import {
  hostMatches,
  checkUrlScope,
  validateScopePolicy,
  validateSolariumConfig,
  validateActions,
  summarizeAgentAction,
  renderSessionMarkdownReport
} from "../dist/index.js";

test("hostMatches supports exact hosts case-insensitively", () => {
  assert.equal(hostMatches("Example.COM", "example.com"), true);
  assert.equal(hostMatches("www.example.com", "example.com"), false);
});

test("hostMatches supports wildcard subdomains without matching apex", () => {
  assert.equal(hostMatches("app.example.com", "*.example.com"), true);
  assert.equal(hostMatches("deep.app.example.com", "*.example.com"), true);
  assert.equal(hostMatches("example.com", "*.example.com"), false);
});

test("checkUrlScope allows, denies, and blocks URLs deterministically", () => {
  const scope = {
    allowedHosts: ["example.com", "*.example.org"],
    blockedHosts: ["blocked.example.org"],
    authorizationNote: "Authorized test scope"
  };

  assert.equal(checkUrlScope("https://example.com/path", scope).allowed, true);
  assert.equal(checkUrlScope("https://app.example.org/path", scope).allowed, true);
  assert.equal(checkUrlScope("https://blocked.example.org/path", scope).allowed, false);
  assert.match(checkUrlScope("https://outside.test/path", scope).reason, /outside allowed scope/);
  assert.match(checkUrlScope("file:///tmp/x", scope).reason, /scheme is not allowed/);
});

test("validateScopePolicy rejects malformed scope policies", () => {
  assert.throws(() => validateScopePolicy({}), /allowedHosts and\/or blockedHosts/);
  assert.throws(() => validateScopePolicy({ allowedHosts: ["https://example.com"] }), /not a full URL/);
  assert.throws(() => validateScopePolicy({ allowedHosts: ["example.com"], maxRequestsPerMinute: 0 }), /positive number/);
  assert.deepEqual(validateScopePolicy({ allowedHosts: ["EXAMPLE.com"] }).allowedHosts, ["example.com"]);
});

test("validateActions accepts all current action primitives", () => {
  const actions = validateActions([
    { type: "navigate", url: "https://example.com" },
    { type: "click", selector: "button" },
    { type: "dblclick", selector: ".editable" },
    { type: "hover", selector: "nav" },
    { type: "type", selector: "input", text: "hello" },
    { type: "press", selector: "input", key: "Enter" },
    { type: "select", selector: "select", values: ["a", "b"] },
    { type: "check", selector: "#yes" },
    { type: "uncheck", selector: "#no" },
    { type: "submit", selector: "form" },
    { type: "upload", selector: "input[type=file]", files: ["a.txt"] },
    { type: "download", selector: "a.download", path: "downloads/file.txt", timeoutMs: 1000 },
    { type: "wait", ms: 1 },
    { type: "waitForSelector", selector: ".ready", state: "visible", timeoutMs: 1000 },
    { type: "waitForUrl", url: "**/dashboard", timeoutMs: 1000 },
    { type: "screenshot", path: "shot.png", fullPage: true },
    { type: "extract", selector: "main", format: "markdown" },
    { type: "observe" }
  ]);

  assert.equal(actions.length, 18);
});

test("validateActions rejects invalid actions with useful messages", () => {
  assert.throws(() => validateActions({}), /must be a JSON array/);
  assert.throws(() => validateActions([{ type: "hover" }]), /selector must be a non-empty string/);
  assert.throws(() => validateActions([{ type: "waitForSelector", selector: ".x", state: "gone" }]), /state must be/);
  assert.throws(() => validateActions([{ type: "waitForUrl", url: "**", timeoutMs: -1 }]), /non-negative number/);
  assert.throws(() => validateActions([{ type: "unknown" }]), /Unsupported action type/);
});

test("validateSolariumConfig infers actions and scope kinds", () => {
  const actionsResult = validateSolariumConfig([{ type: "hover", selector: "nav" }]);
  assert.equal(actionsResult.ok, true);
  assert.equal(actionsResult.kind, "actions");

  const scopeResult = validateSolariumConfig({ allowedHosts: ["example.com"] });
  assert.equal(scopeResult.ok, true);
  assert.equal(scopeResult.kind, "scope");
});

test("summarizeAgentAction redacts typed text length and includes new waits", () => {
  assert.deepEqual(summarizeAgentAction({ type: "type", selector: "#password", text: "secret" }), {
    type: "type",
    selector: "#password",
    textLength: 6
  });
  assert.deepEqual(summarizeAgentAction({ type: "waitForUrl", url: "**/dashboard", timeoutMs: 1000 }), {
    type: "waitForUrl",
    url: "**/dashboard",
    timeoutMs: 1000
  });
});

test("renderSessionMarkdownReport describes new action types", () => {
  const report = renderSessionMarkdownReport({
    sessionId: "test-session",
    startedAt: "2025-01-01T00:00:00.000Z",
    finishedAt: "2025-01-01T00:00:01.000Z",
    ok: true,
    steps: [
      {
        index: 0,
        action: { type: "hover", selector: "nav" },
        startedAt: "2025-01-01T00:00:00.000Z",
        finishedAt: "2025-01-01T00:00:00.100Z",
        ok: true,
        url: "https://example.com",
        title: "Example"
      },
      {
        index: 1,
        action: { type: "waitForSelector", selector: ".ready", state: "visible", timeoutMs: 1000 },
        startedAt: "2025-01-01T00:00:00.100Z",
        finishedAt: "2025-01-01T00:00:00.200Z",
        ok: true,
        url: "https://example.com",
        title: "Example"
      }
    ]
  });

  assert.match(report, /Step 1: hover/);
  assert.match(report, /Step 2: waitForSelector/);
});
