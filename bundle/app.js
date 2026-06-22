const SDK_URL = "/static/anna-apps/_sdk/latest/index.js";
const TOOL_HANDLE = "scamshield-analyzer";
const DEV_FALLBACK_TOOL_ID = "tool-test-scamshield-analyzer-12345678";
const TOOL_ID =
  (typeof window !== "undefined" &&
    window.__ANNA_TOOL_IDS__ &&
    window.__ANNA_TOOL_IDS__[TOOL_HANDLE]) ||
  DEV_FALLBACK_TOOL_ID;
const TOOL_METHOD = "investigate";
const STORAGE_KEY = "scamshield:history:v1";
const MAX_HISTORY = 18;
const MAX_TEXT_CHARS = 12_000;
const MAX_IMAGE_BYTES = 6 * 1024 * 1024;
const ACCEPTED_IMAGE_TYPES = new Set(["image/png", "image/jpeg", "image/webp", "image/gif"]);

const MODES = {
  message: {
    helper: "Paste the suspicious message exactly as received.",
    label: "Message text",
    help: "Include sender text, payment details, links, phone numbers, and deadline language.",
    fields: [],
  },
  website: {
    helper: "Check a suspicious website or shortened link.",
    label: "Context or message around the link",
    help: "Add the message that carried the link if you have it.",
    fields: ["url"],
  },
  email: {
    helper: "Analyze a sender, subject, and email body.",
    label: "Email body",
    help: "Paste the body and include any attachment names or links.",
    fields: ["email"],
  },
  job: {
    helper: "Check whether a job offer is asking for unsafe money or data.",
    label: "Job offer text",
    help: "Include salary, fees, recruiter contact, and company name.",
    fields: [],
  },
  investment: {
    helper: "Look for Ponzi, crypto, forex, and guaranteed-return patterns.",
    label: "Investment pitch",
    help: "Include promised returns, time period, group links, and payment instructions.",
    fields: [],
  },
  qr: {
    helper: "Decode or paste QR contents, then inspect links or payment requests.",
    label: "Decoded QR content",
    help: "Paste decoded text if browser QR detection is unavailable.",
    fields: ["file"],
  },
  screenshot: {
    helper: "Upload a screenshot or paste OCR text from WhatsApp, SMS, or social DMs.",
    label: "OCR text",
    help: "Paste extracted text. Anna extraction can help when the runtime supports image input.",
    fields: ["file"],
  },
};

const SAMPLES = {
  job: {
    mode: "job",
    text: "Amazon Work From Home HR. Salary Rs 60,000 per month. Pay registration fee Rs 500 now to receive your interview letter. Offer valid only today.",
  },
  website: {
    mode: "website",
    url: "amaz0n-sale-offers.xyz",
    text: "Congratulations, your reward is ready. Verify your account immediately.",
  },
  investment: {
    mode: "investment",
    text: "Join our crypto trading signal group. Double your money in 7 days with guaranteed returns and no risk. Limited seats.",
  },
};

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

const els = {
  runtimePill: $("#runtime-pill"),
  runtimeDetail: $("#runtime-detail"),
  modeHelper: $("#mode-helper"),
  evidenceLabel: $("#evidence-label"),
  textHelp: $("#text-help"),
  evidence: $("#evidence-input"),
  url: $("#url-input"),
  sender: $("#sender-input"),
  subject: $("#subject-input"),
  file: $("#file-input"),
  fileLabel: $("#file-label"),
  fileMeta: $("#file-meta"),
  network: $("#network-probe"),
  investigate: $("#investigate-btn"),
  agent: $("#agent-btn"),
  extract: $("#extract-btn"),
  decodeQr: $("#decode-qr-btn"),
  status: $("#status-line"),
  verdictChip: $("#verdict-chip"),
  reportSubtitle: $("#report-subtitle"),
  riskMeter: $("#risk-meter"),
  riskScore: $("#risk-score"),
  riskHeadline: $("#risk-headline"),
  riskSummary: $("#risk-summary"),
  reasons: $("#reason-list"),
  actions: $("#action-list"),
  agentNote: $("#agent-note"),
  save: $("#save-btn"),
  copy: $("#copy-btn"),
  pdf: $("#pdf-link"),
  chat: $("#chat-btn"),
  clearHistory: $("#clear-history-btn"),
  history: $("#history-table"),
  toastStack: $("#toast-stack"),
};

let anna = null;
let currentMode = "message";
let currentReport = null;
let currentPdfUrl = null;
let selectedFile = null;
let historyRecords = [];

init().catch((err) => {
  console.error("[scamshield] init failed", err);
  setStatus(`App failed to start: ${err.message || err}`, "error");
});

async function init() {
  bindUi();
  applyMode("message");
  renderEmptyReport();
  anna = await connectAnna();
  setRuntime(!!anna);
  historyRecords = await loadHistory();
  renderHistory();
  if (anna?.window?.set_title) {
    anna.window.set_title({ title: "ScamShield AI" }).catch(() => {});
  }
}

async function connectAnna() {
  try {
    const probe = await fetch(SDK_URL, { cache: "no-store" });
    if (!probe.ok) {
      console.info("[scamshield] standalone preview");
      return null;
    }
    const mod = await import(SDK_URL);
    const runtime = await mod.AnnaAppRuntime.connect();
    return runtime;
  } catch (err) {
    console.info("[scamshield] standalone preview", err?.message || err);
    return null;
  }
}

function bindUi() {
  for (const btn of $$(".mode-btn")) {
    btn.addEventListener("click", () => applyMode(btn.dataset.mode || "message"));
  }
  for (const btn of $$(".sample-btn")) {
    btn.addEventListener("click", () => applySample(btn.dataset.sample));
  }
  for (const tab of $$(".tab")) {
    tab.addEventListener("click", () => activateTab(tab.dataset.tab || "reasons"));
    tab.addEventListener("keydown", onTabKeydown);
  }
  els.file?.addEventListener("change", onFilePicked);
  els.investigate.addEventListener("click", onInvestigate);
  els.agent.addEventListener("click", () => synthesizeWithAnna(true));
  els.extract.addEventListener("click", extractImageText);
  els.decodeQr.addEventListener("click", decodeQrImage);
  els.save.addEventListener("click", saveCurrentReport);
  els.copy.addEventListener("click", copyRecommendations);
  els.chat.addEventListener("click", sendReportToChat);
  els.clearHistory.addEventListener("click", clearHistory);
}

function setRuntime(connected) {
  els.runtimePill.textContent = connected ? "Anna runtime" : "Standalone";
  els.runtimeDetail.textContent = connected
    ? "Runtime connected. Analyzer, storage, chat, and LLM grants will be used when allowed."
    : "Runtime not connected. Local deterministic fallback is active.";
}

function applyMode(mode) {
  currentMode = MODES[mode] ? mode : "message";
  const spec = MODES[currentMode];
  for (const btn of $$(".mode-btn")) {
    const active = btn.dataset.mode === currentMode;
    btn.classList.toggle("is-active", active);
    btn.setAttribute("aria-pressed", String(active));
  }
  els.modeHelper.textContent = spec.helper;
  els.evidenceLabel.textContent = spec.label;
  els.textHelp.textContent = spec.help;
  for (const field of $$("[data-field]")) {
    field.classList.toggle("is-hidden", !spec.fields.includes(field.dataset.field || ""));
  }
  if (currentMode === "qr") {
    els.fileLabel.textContent = "Upload QR image";
    els.fileMeta.textContent = "Browser QR decode runs locally when supported.";
    els.decodeQr.classList.remove("is-hidden");
    els.extract.classList.add("is-hidden");
  } else if (currentMode === "screenshot") {
    els.fileLabel.textContent = "Upload screenshot";
    els.fileMeta.textContent = "Use Anna extraction or paste OCR text.";
    els.decodeQr.classList.add("is-hidden");
    els.extract.classList.remove("is-hidden");
  }
}

function applySample(name) {
  const sample = SAMPLES[name];
  if (!sample) return;
  applyMode(sample.mode);
  els.evidence.value = sample.text || "";
  els.url.value = sample.url || "";
  setStatus("Sample loaded. Run the investigation.", "");
}

function onFilePicked(event) {
  selectedFile = event.target.files?.[0] || null;
  if (!selectedFile) {
    els.fileMeta.textContent = currentMode === "qr"
      ? "Browser QR decode runs locally when supported."
      : "Use Anna extraction or paste OCR text.";
    return;
  }
  const error = validateImageFile(selectedFile);
  if (error) {
    selectedFile = null;
    event.target.value = "";
    els.fileMeta.textContent = error;
    setStatus(error, "error");
    return;
  }
  els.fileMeta.textContent = `${selectedFile.name} · ${humanBytes(selectedFile.size)}`;
}

function validateImageFile(file) {
  if (!file) return "Choose an image before using this action.";
  if (file.type && !ACCEPTED_IMAGE_TYPES.has(file.type)) {
    return "Use a PNG, JPG, WEBP, or GIF image.";
  }
  if (file.size > MAX_IMAGE_BYTES) {
    return `Image is ${humanBytes(file.size)}. Use an image under ${humanBytes(MAX_IMAGE_BYTES)}.`;
  }
  return "";
}

async function onInvestigate() {
  const payload = readPayload();
  if (!payload.text && !payload.url && !payload.sender && !payload.subject) {
    setStatus("Add evidence before running the analyzer.", "error");
    return;
  }
  if (payload.text.length > MAX_TEXT_CHARS) {
    payload.text = payload.text.slice(0, MAX_TEXT_CHARS);
    setStatus("Text is long; analyzing the first 12,000 characters.", "");
  }
  setBusy(true);
  if (els.status.textContent !== "Text is long; analyzing the first 12,000 characters.") {
    setStatus("Running evidence engine...", "");
  }
  try {
    const report = await investigate(payload);
    currentReport = report;
    renderReport(report);
    createPdfUrl(report);
    setStatus("Investigation complete.", "");
    if (anna?.llm?.complete) {
      els.agent.disabled = false;
      void synthesizeWithAnna(false);
    }
  } catch (err) {
    console.error(err);
    setStatus(`Investigation failed: ${err.message || err}`, "error");
    toast(`Investigation failed: ${err.message || err}`);
  } finally {
    setBusy(false);
  }
}

function readPayload() {
  return {
    mode: currentMode,
    text: els.evidence.value.trim(),
    url: els.url.value.trim(),
    sender: els.sender.value.trim(),
    subject: els.subject.value.trim(),
    filename: selectedFile?.name || "",
    allow_network: !!els.network.checked,
  };
}

async function investigate(payload) {
  if (anna?.tools?.invoke) {
    try {
      const reply = await anna.tools.invoke(
        { tool_id: TOOL_ID, method: TOOL_METHOD, args: payload, timeoutMs: 65_000 },
        { timeoutMs: 70_000 },
      );
      const unwrapped = unwrapToolReply(reply);
      if (unwrapped) return unwrapped;
    } catch (err) {
      console.warn("[scamshield] tool invoke failed; using fallback", err);
      setStatus("Anna tool unavailable. Using local fallback analyzer.", "");
    }
  }
  return localAnalyze(payload);
}

function unwrapToolReply(reply) {
  if (!reply) return null;
  if (reply.data && reply.success !== false) return reply.data;
  if (reply.success === true && reply.tool && reply.data) return reply.data;
  if (reply.score != null && reply.findings) return reply;
  if (reply.success === false) throw new Error(reply.error || "Analyzer returned an error");
  return reply.data || null;
}

function extractLlmText(response) {
  const candidates = [
    response?.content,
    response?.message?.content,
    response?.result?.content,
    response?.data?.content,
    response?.text,
    response?.output_text,
    response?.result?.text,
    response?.data?.text,
    response?.choices?.[0]?.message?.content,
    response?.choices?.[0]?.text,
  ];
  for (const candidate of candidates) {
    const text = textFromContent(candidate);
    if (text) return text;
  }
  return "";
}

function textFromContent(content) {
  if (!content) return "";
  if (typeof content === "string") return content.trim();
  if (Array.isArray(content)) {
    return content.map(textFromContent).filter(Boolean).join("\n").trim();
  }
  if (typeof content === "object") {
    return textFromContent(content.text || content.value || content.content || content.message);
  }
  return "";
}

function fallbackAgentNote(report) {
  const findings = (report.findings || []).slice(0, 3).map((finding) => finding.title.toLowerCase());
  const actions = (report.recommendations || []).slice(0, 2).map((rec) => rec.action.toLowerCase());
  const limitations = (report.limitations || []).slice(0, 2);
  const why = findings.length ? findings.join(", ") : "limited but suspicious evidence";
  const next = actions.length ? actions.join("; ") : "pause and verify through an official channel";
  const missing = limitations.length ? limitations.join(" ") : "Missing live reputation and authority data should be verified independently.";
  return `Evidence-based investigator note: ${report.headline || "Suspicious content"} with ${report.score ?? "--"}% risk. The main signals are ${why}. Next step: ${next}. Evidence gap: ${missing}`;
}

async function synthesizeWithAnna(interactive) {
  if (!currentReport || !anna?.llm?.complete) {
    if (interactive) toast("Anna LLM synthesis is unavailable in this runtime.");
    return;
  }
  els.agent.disabled = true;
  els.agentNote.textContent = "Anna is reviewing the evidence...";
  try {
    const response = await anna.llm.complete({
      systemPrompt:
        "You are ScamShield AI. Explain fraud risk using only the JSON evidence. Do not invent domain age, user reports, breach data, or facts not in the evidence. Be concise and action-oriented.",
      messages: [
        {
          role: "user",
          content: {
            type: "text",
            text:
              "Write a short investigator note for this report. Include: verdict, why it is risky, what the user should do next, and what evidence is missing.\n\n" +
              (currentReport.llm_context || JSON.stringify(compactReport(currentReport))),
          },
        },
      ],
      maxTokens: 360,
      temperature: 0.2,
      modelPreferences: { speedPriority: 0.45, intelligencePriority: 0.75 },
      metadata: { source: "scamshield-ai", report_id: currentReport.id },
    });
    const text = extractLlmText(response);
    currentReport.agent_note = text || fallbackAgentNote(currentReport);
    els.agentNote.textContent = currentReport.agent_note;
    activateTab("agent");
    createPdfUrl(currentReport);
  } catch (err) {
    els.agentNote.textContent =
      "Anna synthesis failed. The deterministic evidence report is still available.";
    console.warn("[scamshield] llm synthesis failed", err);
    if (interactive) toast(`Anna synthesis failed: ${err.message || err}`);
  } finally {
    els.agent.disabled = false;
  }
}

async function extractImageText() {
  if (!selectedFile) {
    toast("Choose a screenshot first.");
    return;
  }
  if (!anna?.llm?.complete) {
    toast("Anna image extraction needs the Anna runtime. Paste OCR text for standalone testing.");
    return;
  }
  setBusy(true);
  setStatus("Asking Anna to extract screenshot text...", "");
  try {
    const dataUrl = await fileToDataUrl(selectedFile);
    const response = await anna.llm.complete({
      systemPrompt:
        "Extract visible text from the image. Return only the text, preserving links, phone numbers, amounts, and sender names. If unreadable, say UNREADABLE.",
      messages: [
        {
          role: "user",
          content: {
            type: "image",
            image_url: dataUrl,
          },
        },
      ],
      maxTokens: 700,
      temperature: 0,
    });
    const text = extractLlmText(response);
    if (text && text !== "UNREADABLE") {
      els.evidence.value = text.trim();
      setStatus("Screenshot text extracted.", "");
    } else {
      setStatus("Anna could not read the screenshot. Paste the text manually.", "error");
    }
  } catch (err) {
    setStatus(`Extraction failed: ${err.message || err}`, "error");
  } finally {
    setBusy(false);
  }
}

async function decodeQrImage() {
  if (!selectedFile) {
    toast("Choose a QR image first.");
    return;
  }
  setBusy(true);
  setStatus("Decoding QR image...", "");
  try {
    const decoded = await decodeQrLocally(selectedFile);
    if (decoded) {
      els.evidence.value = decoded;
      setStatus("QR code decoded locally.", "");
      return;
    }
    if (anna?.llm?.complete) {
      const dataUrl = await fileToDataUrl(selectedFile);
      const response = await anna.llm.complete({
        systemPrompt:
          "Read the QR code in the image. Return only the decoded URL/payment/text. If not readable, say UNREADABLE.",
        messages: [{ role: "user", content: { type: "image", image_url: dataUrl } }],
        maxTokens: 300,
        temperature: 0,
      });
      const text = extractLlmText(response);
      if (text && text !== "UNREADABLE") {
        els.evidence.value = text.trim();
        setStatus("QR code decoded with Anna.", "");
        return;
      }
    }
    setStatus("QR decoding is not available for this image. Paste decoded text manually.", "error");
  } catch (err) {
    setStatus(`QR decode failed: ${err.message || err}`, "error");
  } finally {
    setBusy(false);
  }
}

async function decodeQrLocally(file) {
  if (!("BarcodeDetector" in window)) return "";
  const detector = new window.BarcodeDetector({ formats: ["qr_code"] });
  const bitmap = await createImageBitmap(file);
  const codes = await detector.detect(bitmap);
  return codes?.[0]?.rawValue || "";
}

function renderEmptyReport() {
  els.riskMeter.dataset.risk = "none";
  els.riskMeter.style.setProperty("--score", "0");
  els.riskScore.textContent = "--";
  els.verdictChip.textContent = "No scan";
  els.riskHeadline.textContent = "Awaiting evidence";
  els.riskSummary.textContent = "Paste or upload content, then run the analyzer.";
  els.reasons.innerHTML = `<li class="empty-row">No findings yet.</li>`;
  els.actions.innerHTML = `<li class="empty-row">Recommended actions will appear here.</li>`;
  els.agentNote.textContent = "Anna synthesis has not run for this report.";
  for (const el of [els.save, els.copy, els.chat]) el.disabled = true;
  els.pdf.classList.add("is-disabled");
}

function renderReport(report) {
  const risk = report.verdict === "dangerous" ? "dangerous" : report.verdict === "high_risk" ? "high" : report.verdict;
  els.riskMeter.dataset.risk = risk || "low";
  els.riskMeter.style.setProperty("--score", String(report.score || 0));
  els.riskScore.textContent = `${report.score ?? 0}%`;
  els.verdictChip.textContent = labelVerdict(report.verdict);
  els.reportSubtitle.textContent = `${report.mode} · ${report.confidence || "medium"} confidence`;
  els.riskHeadline.textContent = report.headline || "Investigation complete";
  els.riskSummary.textContent = report.summary || "";
  renderFindings(report.findings || []);
  renderActions(report.recommendations || []);
  els.agentNote.textContent = report.agent_note || "Anna synthesis has not run for this report.";
  for (const el of [els.save, els.copy, els.chat]) el.disabled = false;
  els.pdf.classList.remove("is-disabled");
}

function renderFindings(findings) {
  els.reasons.innerHTML = "";
  if (!findings.length) {
    els.reasons.innerHTML = `<li class="empty-row">No high-confidence scam indicators were detected.</li>`;
    return;
  }
  for (const finding of findings) {
    const li = document.createElement("li");
    li.className = "reason-item";
    li.innerHTML = `
      <strong>${escapeHtml(finding.title)}</strong>
      <span class="reason-meta">${escapeHtml(finding.severity)} · +${Number(finding.points || 0)} risk</span>
      <span>${escapeHtml(finding.evidence || "")}</span>
      <span>${escapeHtml(finding.recommendation || "")}</span>
    `;
    els.reasons.appendChild(li);
  }
}

function renderActions(actions) {
  els.actions.innerHTML = "";
  if (!actions.length) {
    els.actions.innerHTML = `<li class="empty-row">No action recommendations returned.</li>`;
    return;
  }
  for (const action of actions) {
    const li = document.createElement("li");
    li.className = "action-item";
    li.innerHTML = `
      <strong>${escapeHtml(action.action || "")}</strong>
      <span>${escapeHtml(action.why || "")}</span>
    `;
    els.actions.appendChild(li);
  }
}

async function saveCurrentReport() {
  if (!currentReport) return;
  const compact = compactReport(currentReport);
  historyRecords = [compact, ...historyRecords.filter((r) => r.id !== compact.id)].slice(0, MAX_HISTORY);
  await saveHistory(historyRecords);
  renderHistory();
  toast("Report saved.");
}

function compactReport(report) {
  return {
    id: report.id,
    created_at: report.created_at,
    mode: report.mode,
    score: report.score,
    verdict: report.verdict,
    headline: report.headline,
    summary: report.summary,
    findings: (report.findings || []).slice(0, 6),
    recommendations: (report.recommendations || []).slice(0, 6),
    limitations: (report.limitations || []).slice(0, 4),
    input_excerpt: report.input_excerpt || "",
    agent_note: report.agent_note || "",
  };
}

async function loadHistory() {
  try {
    if (anna?.storage?.get) {
      const result = await anna.storage.get({ key: STORAGE_KEY });
      const value = result?.value;
      if (Array.isArray(value)) return value;
      if (typeof value === "string") return JSON.parse(value);
    }
  } catch (err) {
    console.warn("[scamshield] storage get failed", err);
  }
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY) || "[]");
  } catch {
    return [];
  }
}

async function saveHistory(records) {
  const compact = records.slice(0, MAX_HISTORY);
  try {
    if (anna?.storage?.set) {
      await anna.storage.set({ key: STORAGE_KEY, value: compact });
    }
  } catch (err) {
    console.warn("[scamshield] storage set failed", err);
  }
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(compact));
  } catch {
    /* ignore local quota */
  }
}

function renderHistory() {
  els.history.innerHTML = "";
  if (!historyRecords.length) {
    els.history.innerHTML = `<p class="empty-row">No saved investigations yet.</p>`;
    return;
  }
  for (const record of historyRecords) {
    const row = document.createElement("div");
    row.className = "history-row";
    row.setAttribute("role", "listitem");
    row.innerHTML = `
      <button type="button" class="history-row__main">
        <span class="history-row__title">${escapeHtml(record.headline || "Saved report")}</span>
        <span class="history-row__meta">${escapeHtml(record.mode || "scan")} · ${formatTime(record.created_at)}</span>
      </button>
      <span class="history-row__score">${Number(record.score || 0)}% · ${escapeHtml(labelVerdict(record.verdict))}</span>
    `;
    row.querySelector("button")?.addEventListener("click", () => {
      currentReport = { ...record, report_markdown: markdownFromCompact(record) };
      renderReport(currentReport);
      createPdfUrl(currentReport);
      window.scrollTo({ top: 0, behavior: "smooth" });
    });
    els.history.appendChild(row);
  }
}

async function clearHistory() {
  if (!historyRecords.length) {
    toast("History is already empty.");
    return;
  }
  const previousRecords = historyRecords.slice();
  historyRecords = [];
  await saveHistory(historyRecords);
  renderHistory();
  toast("History cleared.", {
    actionLabel: "Undo",
    onAction: async () => {
      historyRecords = previousRecords;
      await saveHistory(historyRecords);
      renderHistory();
      toast("History restored.");
    },
  });
}

async function copyRecommendations() {
  if (!currentReport) return;
  const text = (currentReport.recommendations || [])
    .map((rec) => `- ${rec.action}: ${rec.why}`)
    .join("\n");
  try {
    await navigator.clipboard.writeText(text || currentReport.summary || "");
    els.copy.dataset.state = "copied";
    toast("Recommendations copied.");
    setTimeout(() => delete els.copy.dataset.state, 2200);
  } catch {
    toast("Clipboard is unavailable in this runtime.");
  }
}

async function sendReportToChat() {
  if (!currentReport || !anna?.chat?.write_message) {
    toast("Anna chat is unavailable in this runtime.");
    return;
  }
  await anna.chat.write_message({
    role: "user",
    content: chatPromptFromReport(currentReport),
  });
  toast("Report sent to Anna chat.");
}

function chatPromptFromReport(report) {
  const findings = (report.findings || [])
    .slice(0, 6)
    .map((finding) => `- ${finding.severity}: ${finding.title} - ${finding.evidence}`)
    .join("\n") || "- No high-confidence indicators.";
  const actions = (report.recommendations || [])
    .slice(0, 6)
    .map((rec) => `- ${rec.action}: ${rec.why}`)
    .join("\n") || "- No recommendations returned.";
  const limitations = (report.limitations || [])
    .slice(0, 4)
    .map((note) => `- ${note}`)
    .join("\n") || "- No limitations returned.";
  return [
    `ScamShield report ${report.id || "scan"}`,
    `Verdict: ${report.headline || "Unknown"} (${report.score ?? "--"}% risk, ${report.confidence || "unknown"} confidence)`,
    `Mode: ${report.mode || "scan"}`,
    "",
    "Findings:",
    findings,
    "",
    "Recommended actions:",
    actions,
    "",
    "Limitations:",
    limitations,
    "",
    `Evidence excerpt: ${report.input_excerpt || "No excerpt stored."}`,
    "",
    "Please help me decide the safest next step using only this report evidence.",
  ].join("\n");
}

function createPdfUrl(report) {
  if (currentPdfUrl) URL.revokeObjectURL(currentPdfUrl);
  const pdfBytes = buildSimplePdf(report);
  currentPdfUrl = URL.createObjectURL(new Blob([pdfBytes], { type: "application/pdf" }));
  els.pdf.href = currentPdfUrl;
  els.pdf.download = `scamshield-report-${report.id || "scan"}.pdf`;
}

function buildSimplePdf(report) {
  const lines = markdownFromCompact(report)
    .replace(/^#+\s*/gm, "")
    .split(/\r?\n/)
    .flatMap((line) => wrapLine(line, 88));
  const pages = chunkLines(lines, 50);
  const objects = [];
  const addObject = (body) => {
    objects.push(body);
    return objects.length;
  };
  const catalogId = addObject("");
  const pagesId = addObject("");
  const fontId = addObject("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>");
  const pageIds = [];

  pages.forEach((pageLines, index) => {
    const pageContent = [
      "BT",
      "/F1 10 Tf",
      "50 790 Td",
      "14 TL",
      ...pageLines.map((line, i) => `${i === 0 ? "" : "T* "}${pdfText(line)} Tj`),
      "T*",
      `${pdfText(`Page ${index + 1} of ${pages.length}`)} Tj`,
      "ET",
    ].join("\n");
    const contentId = addObject(`<< /Length ${byteLength(pageContent)} >>\nstream\n${pageContent}\nendstream`);
    const pageId = addObject(`<< /Type /Page /Parent ${pagesId} 0 R /MediaBox [0 0 612 842] /Resources << /Font << /F1 ${fontId} 0 R >> >> /Contents ${contentId} 0 R >>`);
    pageIds.push(pageId);
  });

  objects[catalogId - 1] = `<< /Type /Catalog /Pages ${pagesId} 0 R >>`;
  objects[pagesId - 1] = `<< /Type /Pages /Kids [${pageIds.map((id) => `${id} 0 R`).join(" ")}] /Count ${pageIds.length} >>`;
  let pdf = "%PDF-1.4\n";
  const offsets = [0];
  for (let i = 0; i < objects.length; i++) {
    offsets.push(pdf.length);
    pdf += `${i + 1} 0 obj\n${objects[i]}\nendobj\n`;
  }
  const xref = pdf.length;
  pdf += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (let i = 1; i < offsets.length; i++) {
    pdf += `${String(offsets[i]).padStart(10, "0")} 00000 n \n`;
  }
  pdf += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF`;
  return new TextEncoder().encode(pdf);
}

function chunkLines(lines, pageSize) {
  const chunks = [];
  for (let i = 0; i < lines.length; i += pageSize) {
    chunks.push(lines.slice(i, i + pageSize));
  }
  return chunks.length ? chunks : [["ScamShield AI report"]];
}

function pdfText(text) {
  return `(${String(text).replace(/\\/g, "\\\\").replace(/\(/g, "\\(").replace(/\)/g, "\\)")})`;
}

function byteLength(text) {
  return new TextEncoder().encode(text).length;
}

function markdownFromCompact(report) {
  if (report.report_markdown) return report.report_markdown;
  const lines = [
    "ScamShield AI report",
    "",
    `Report ID: ${report.id || "--"}`,
    `Created: ${report.created_at || "--"}`,
    `Mode: ${report.mode || "--"}`,
    `Verdict: ${report.headline || "--"}`,
    `Risk score: ${report.score ?? "--"}%`,
    "",
    "Reasons",
    ...(report.findings || []).map((f) => `- ${f.severity}: ${f.title} - ${f.evidence}`),
    "",
    "Recommended actions",
    ...(report.recommendations || []).map((r) => `- ${r.action}: ${r.why}`),
  ];
  if (report.limitations?.length) {
    lines.push("", "Limitations", ...(report.limitations || []).map((note) => `- ${note}`));
  }
  if (report.agent_note) lines.push("", "Anna note", report.agent_note);
  return lines.join("\n");
}

function wrapLine(line, width) {
  if (!line) return [""];
  const words = line.split(/\s+/);
  const lines = [];
  let current = "";
  for (const word of words) {
    if ((current + " " + word).trim().length > width) {
      lines.push(current);
      current = word;
    } else {
      current = `${current} ${word}`.trim();
    }
  }
  if (current) lines.push(current);
  return lines;
}

function onTabKeydown(event) {
  const tabs = $$(".tab");
  const currentIndex = tabs.indexOf(event.currentTarget);
  if (currentIndex < 0) return;
  const keyMap = {
    ArrowRight: (currentIndex + 1) % tabs.length,
    ArrowDown: (currentIndex + 1) % tabs.length,
    ArrowLeft: (currentIndex - 1 + tabs.length) % tabs.length,
    ArrowUp: (currentIndex - 1 + tabs.length) % tabs.length,
    Home: 0,
    End: tabs.length - 1,
  };
  if (!(event.key in keyMap)) return;
  event.preventDefault();
  const next = tabs[keyMap[event.key]];
  activateTab(next.dataset.tab || "reasons", { focus: true });
}

function activateTab(name, options = {}) {
  for (const tab of $$(".tab")) {
    const active = tab.dataset.tab === name;
    tab.classList.toggle("is-active", active);
    tab.setAttribute("aria-selected", String(active));
    tab.tabIndex = active ? 0 : -1;
    if (active && options.focus) tab.focus({ preventScroll: true });
  }
  for (const panel of $$(".tab-panel")) {
    const active = panel.dataset.panel === name;
    panel.classList.toggle("is-active", active);
    panel.hidden = !active;
  }
}

function setBusy(on) {
  els.investigate.disabled = !!on;
  document.body.classList.toggle("is-busy", !!on);
}

function setStatus(text, kind) {
  els.status.textContent = text;
  if (kind) els.status.dataset.kind = kind;
  else delete els.status.dataset.kind;
}

function toast(message, options = {}) {
  const el = document.createElement("div");
  el.className = "toast";
  const text = document.createElement("span");
  text.textContent = message;
  el.appendChild(text);
  if (options.actionLabel && typeof options.onAction === "function") {
    const action = document.createElement("button");
    action.className = "toast__action";
    action.type = "button";
    action.textContent = options.actionLabel;
    action.addEventListener("click", async () => {
      await options.onAction();
      el.remove();
    }, { once: true });
    el.appendChild(action);
  }
  els.toastStack.appendChild(el);
  setTimeout(() => el.remove(), options.duration || 7000);
}

function labelVerdict(verdict) {
  return {
    dangerous: "Dangerous",
    high_risk: "High risk",
    suspicious: "Suspicious",
    low_risk: "Low risk",
  }[verdict] || "No scan";
}

function formatTime(value) {
  if (!value) return "--";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

function humanBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

async function fileToDataUrl(file) {
  const error = validateImageFile(file);
  if (error) throw new Error(error);
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result || ""));
    reader.onerror = () => reject(reader.error || new Error("file read failed"));
    reader.readAsDataURL(file);
  });
}

function localAnalyze(payload) {
  const text = [payload.subject, payload.sender, payload.url, payload.text, payload.filename]
    .filter(Boolean)
    .join(" ")
    .trim();
  const findings = [];
  const entities = extractEntities(text);
  analyzeLocalUrl(payload.url || entities.urls[0] || "", text, findings);
  keywordFindings(text, findings);
  modeRules(payload.mode, text, findings);
  const dedup = [];
  const seen = new Set();
  for (const finding of findings.sort((a, b) => b.points - a.points)) {
    const key = `${finding.title}:${finding.evidence}`;
    if (!seen.has(key)) {
      seen.add(key);
      dedup.push(finding);
    }
  }
  let score = 8 + dedup.reduce((sum, item) => sum + Math.max(0, item.points), 0);
  if (dedup.length >= 5) score += 8;
  if (dedup.some((item) => item.points >= 22) && dedup.length >= 2) score += 6;
  score = Math.max(0, Math.min(99, score));
  const verdict = score >= 80 ? "dangerous" : score >= 55 ? "high_risk" : score >= 30 ? "suspicious" : "low_risk";
  const headline = headlineFor(verdict, payload.mode);
  const report = {
    id: `ss-${crypto.randomUUID().replace(/-/g, "").slice(0, 12)}`,
    created_at: new Date().toISOString(),
    mode: payload.mode,
    score,
    verdict,
    headline,
    summary: dedup.length ? `Top evidence: ${dedup.slice(0, 3).map((f) => f.title.toLowerCase()).join(", ")}.` : "No high-confidence scam pattern was detected in the supplied content.",
    findings: dedup.slice(0, 12),
    recommendations: recommendationsFor(verdict, dedup, payload.mode),
    entities,
    limitations: [
      "ScamShield uses deterministic pattern analysis and should support, not replace, human verification.",
      "Live domain age, breach reputation, and community report counts were not checked in standalone fallback.",
    ],
    confidence: dedup.length >= 3 && score >= 70 ? "high" : dedup.length ? "medium" : "low",
    input_excerpt: text.slice(0, 800),
  };
  report.report_markdown = markdownFromCompact(report);
  report.llm_context = JSON.stringify(compactReport(report));
  return report;
}

function extractEntities(text) {
  return {
    urls: unique(text.match(/https?:\/\/[^\s<>()]+|(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:\/[^\s<>()]*)?/g)).slice(0, 10),
    phones: unique(text.match(/(?:\+?\d[\d\s().-]{7,}\d)/g)).slice(0, 10).map((v) => v.trim()),
    emails: unique(text.match(/[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}/g)).slice(0, 10),
    amounts: unique(text.match(/(?:rs\.?|inr|\$|usd|eur|gbp)\s?[\d,]+(?:\.\d+)?|[\d,]+(?:\.\d+)?\s?(?:rs|inr|usd|eur|gbp)/gi)).slice(0, 10),
  };
}

function analyzeLocalUrl(url, text, findings) {
  const raw = url || (extractEntities(text).urls[0] || "");
  if (!raw) return;
  const normalized = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `https://${raw}`;
  let parsed;
  try {
    parsed = new URL(normalized);
  } catch {
    return;
  }
  const host = parsed.hostname.toLowerCase();
  const tld = host.split(".").pop();
  if (parsed.protocol !== "https:") addFinding(findings, 10, "Link is not HTTPS", normalized, "Do not enter credentials or payment details on non-HTTPS links.");
  if (["xyz", "top", "click", "work", "loan", "biz"].includes(tld)) addFinding(findings, 10, "Higher-risk domain ending", `.${tld}`, "Verify the domain through the official brand website or app.");
  if (/\d/.test(host) && /(amazon|paytm|paypal|apple|google|microsoft)/.test(host)) addFinding(findings, 18, "Brand name mixed with digits", host, "Treat lookalike brand domains as suspicious until independently verified.");
  const brands = ["amazon", "paypal", "paytm", "apple", "google", "microsoft", "instagram", "whatsapp"];
  const label = host.split(".")[0].replaceAll("0", "o").replaceAll("1", "l");
  for (const brand of brands) {
    if (label.includes(brand) && label !== brand) {
      addFinding(findings, 18, "Possible brand impersonation", `${host} resembles ${brand}`, "Open the brand by typing its official domain yourself.");
      break;
    }
  }
}

function keywordFindings(text, findings) {
  const rules = [
    [/urgent|immediately|act now|last chance|only today/i, 14, "Urgency pressure", "Scammers pressure victims to act before verifying."],
    [/won|winner|prize|lottery|free money|gift card|cashback/i, 16, "Unexpected reward", "Unexpected money or prizes are common lure patterns."],
    [/pay.*(fee|charge|deposit|registration|processing)|registration fee|security deposit/i, 22, "Upfront payment request", "Legitimate hiring or prize claims rarely require advance payment."],
    [/pin|otp|one[- ]time password|password|verify your account|kyc/i, 22, "Credential or OTP request", "A request for OTP, PIN, password, or KYC data can enable account takeover."],
    [/remote access|anydesk|teamviewer|install this app|screen share/i, 20, "Remote access request", "Remote access requests are high-risk in support and refund scams."],
    [/guaranteed returns?|double your money|profit guaranteed|no risk|\d+%\s*(daily|weekly|monthly)/i, 26, "Guaranteed-return investment claim", "Guaranteed high returns are a strong Ponzi or investment-scam signal."],
    [/crypto|forex|binary option|trading signal|telegram group/i, 12, "Speculative investment channel", "Scams often route victims into crypto, forex, or signal groups."],
    [/interview letter|work from home|salary.*\d{4,}|joining kit|\bhr\b/i, 8, "Job-offer language", "Job scams commonly combine attractive salary claims with pressure or fees."],
  ];
  for (const [pattern, points, title, recommendation] of rules) {
    const match = text.match(pattern);
    if (match) addFinding(findings, points, title, snippet(text, match.index || 0, (match.index || 0) + match[0].length), recommendation);
  }
}

function modeRules(mode, text, findings) {
  if (mode === "job" && /(fee|deposit|registration|training charge|kit charge)/i.test(text)) {
    addFinding(findings, 24, "Job offer asks for money", "Fee/deposit language found", "Do not pay before employment. Verify through the company's official careers site.");
  }
  if (mode === "investment" && /(guaranteed|double|fixed return|no risk)/i.test(text)) {
    addFinding(findings, 26, "Investment claim removes normal risk", "Guaranteed/no-risk return language found", "Do not send money. Verify registration with the relevant financial regulator.");
  }
  if (mode === "qr" && /(upi:\/\/|pa=|paytmmp:\/\/|phonepe:\/\/)/i.test(text)) {
    addFinding(findings, 14, "QR code contains payment instructions", text.slice(0, 180), "Receiving money never requires entering a UPI PIN. Confirm amount and payee before scanning.");
  }
}

function addFinding(findings, points, title, evidence, recommendation) {
  findings.push({ title, severity: severity(points), points, evidence: String(evidence).slice(0, 240), recommendation });
}

function severity(points) {
  if (points >= 22) return "critical";
  if (points >= 14) return "high";
  if (points >= 7) return "medium";
  return "low";
}

function snippet(text, start, end) {
  return text.slice(Math.max(0, start - 45), Math.min(text.length, end + 45)).replace(/\s+/g, " ").trim();
}

function headlineFor(verdict, mode) {
  const noun = { website: "website", email: "email", job: "job offer", investment: "investment pitch", qr: "QR code", screenshot: "screenshot" }[mode] || "message";
  if (verdict === "dangerous") return `Likely scam ${noun}`;
  if (verdict === "high_risk") return `High-risk ${noun}`;
  if (verdict === "suspicious") return `Suspicious ${noun}`;
  return `No strong scam pattern found in this ${noun}`;
}

function recommendationsFor(verdict, findings, mode) {
  const titles = new Set(findings.map((f) => f.title));
  const recs = [];
  if (["dangerous", "high_risk"].includes(verdict)) {
    recs.push({ action: "Do not click, pay, or reply", why: "The evidence has multiple high-risk scam indicators." });
    recs.push({ action: "Verify through an official channel", why: "Use a bookmarked website, official app, or known phone number." });
  } else if (verdict === "suspicious") {
    recs.push({ action: "Pause and verify first", why: "The content has enough risk signals to avoid immediate action." });
  } else {
    recs.push({ action: "Still verify sensitive requests", why: "Low risk is not the same as guaranteed safe." });
  }
  if (titles.has("Credential or OTP request")) recs.push({ action: "Never share OTP, PIN, or password", why: "These can give an attacker direct account access." });
  if (titles.has("Upfront payment request") || titles.has("Job offer asks for money")) recs.push({ action: "Do not pay a hiring or release fee", why: "Advance-payment requests are a core job and prize scam pattern." });
  if (mode === "qr") recs.push({ action: "Check the payee and amount on your payment app", why: "QR codes can silently encode a payment request." });
  return recs.slice(0, 6);
}

function unique(values) {
  return Array.from(new Set(values || []));
}
