/**
 * SecureLLM Content Script
 * Injected into ChatGPT, Gemini, and Claude.
 * Intercepts the send button click, screens the prompt via Flask,
 * and shows a floating badge with the result.
 */

(function () {
  "use strict";

  // ─────────────────────────────────────────────────────────────
  // 1. Site Detection
  // ─────────────────────────────────────────────────────────────
  const SITE = (() => {
    const h = location.hostname;
    if (h.includes("openai.com") || h.includes("chatgpt.com")) return "chatgpt";
    if (h.includes("gemini.google.com")) return "gemini";
    if (h.includes("claude.ai")) return "claude";
    return "unknown";
  })();

  if (SITE === "unknown") return;

  // ─────────────────────────────────────────────────────────────
  // 2. Selectors per site
  // ─────────────────────────────────────────────────────────────
  const SELECTORS = {
    chatgpt: {
      input: [
        "#prompt-textarea",
        "div[contenteditable='true'][data-placeholder]",
        "textarea[tabindex='0']"
      ],
      send: [
        "button[data-testid='send-button']",
        "button[aria-label='Send prompt']",
        "button[aria-label='Send message']"
      ]
    },
    gemini: {
      input: [
        ".ql-editor",
        "div[contenteditable='true']",
        "rich-textarea div[contenteditable]"
      ],
      send: [
        "button.send-button",
        "button[aria-label='Send message']",
        "button[data-test-id='send-button']",
        "mat-icon[data-mat-icon-name='send']"
      ]
    },
    claude: {
      input: [
        "div[contenteditable='true']",
        ".ProseMirror",
        "div[role='textbox']"
      ],
      send: [
        "button[aria-label='Send Message']",
        "button[data-value='send']",
        "button[type='submit']"
      ]
    }
  };

  // ─────────────────────────────────────────────────────────────
  // 3. State
  // ─────────────────────────────────────────────────────────────
  let isEnabled = true;
  let threshold = 0.5;
  let badgeTimeout = null;
  let pendingScan = false;

  // Load settings from storage
  chrome.storage.local.get(["securellm_enabled", "securellm_threshold"], data => {
    if (typeof data.securellm_enabled === "boolean") isEnabled = data.securellm_enabled;
    if (typeof data.securellm_threshold === "number") threshold = data.securellm_threshold;
  });

  // Listen for live setting updates from popup
  chrome.runtime.onMessage.addListener(msg => {
    if (msg.type === "SETTINGS_UPDATED") {
      if (typeof msg.enabled === "boolean") isEnabled = msg.enabled;
      if (typeof msg.threshold === "number") threshold = msg.threshold;
    }
  });

  // ─────────────────────────────────────────────────────────────
  // 4. Badge UI
  // ─────────────────────────────────────────────────────────────
  function createBadge() {
    const existing = document.getElementById("securellm-badge");
    if (existing) return existing;

    const badge = document.createElement("div");
    badge.id = "securellm-badge";
    badge.innerHTML = `
      <div class="slm-inner">
        <span class="slm-icon"></span>
        <span class="slm-text">SecureLLM</span>
      </div>
    `;
    document.body.appendChild(badge);
    return badge;
  }

  function showBadge(state, title, detail, duration) {
    const badge = createBadge();
    badge.className = ""; // reset
    badge.id = "securellm-badge";
    badge.classList.add(`slm-${state}`);

    const icon = badge.querySelector(".slm-icon");
    const text = badge.querySelector(".slm-text");

    const icons = { scanning: "⟳", safe: "✓", flagged: "⚠", blocked: "✗", error: "!" };
    icon.textContent = icons[state] || "?";
    text.innerHTML = `<strong>${title}</strong>${detail ? `<br><span class="slm-detail">${detail}</span>` : ""}`;

    badge.classList.add("slm-visible");
    if (badgeTimeout) clearTimeout(badgeTimeout);

    if (duration > 0) {
      badgeTimeout = setTimeout(() => hideBadge(), duration);
    }
  }

  function hideBadge() {
    const badge = document.getElementById("securellm-badge");
    if (badge) badge.classList.remove("slm-visible");
  }

  // ─────────────────────────────────────────────────────────────
  // 5. Get prompt text
  // ─────────────────────────────────────────────────────────────
  function getPromptText() {
    const sels = SELECTORS[SITE]?.input || [];
    for (const sel of sels) {
      const el = document.querySelector(sel);
      if (el) {
        return (el.value || el.innerText || el.textContent || "").trim();
      }
    }
    return "";
  }

  // ─────────────────────────────────────────────────────────────
  // 6. Screen the prompt
  // ─────────────────────────────────────────────────────────────
  async function screenAndNotify() {
    if (!isEnabled || pendingScan) return;

    const prompt = getPromptText();
    if (!prompt || prompt.length < 3) return;

    pendingScan = true;
    showBadge("scanning", "Scanning...", null, 0);

    try {
      const response = await new Promise((resolve, reject) => {
        chrome.runtime.sendMessage(
          { type: "SCREEN_PROMPT", prompt, threshold },
          res => {
            if (chrome.runtime.lastError) reject(new Error(chrome.runtime.lastError.message));
            else resolve(res);
          }
        );
      });

      if (!response.ok) {
        showBadge("error", "SecureLLM offline", "Run: python app.py", 5000);
        return;
      }

      const result = response.result;

      if (!result.allowed) {
        // Blocked
        const layerName = result.layer_blocked === 1
          ? "Heuristic Rule"
          : result.layer_blocked === 2
          ? "ML Classifier"
          : "Defense";
        showBadge(
          "blocked",
          `Attack detected · ${layerName}`,
          result.reason || "",
          10000
        );
      } else if (result.findings && result.findings.length > 0) {
        // Flagged but allowed
        const highSev = result.findings.find(f => f.severity === "HIGH");
        const topFinding = highSev || result.findings[0];
        const scoreStr = result.threat_score > 0
          ? ` · ${Math.round(result.threat_score * 100)}% risk`
          : "";
        showBadge(
          "flagged",
          `Suspicious · ${topFinding.rule_name}${scoreStr}`,
          topFinding.description || "",
          8000
        );
      } else if (result.threat_score > 0.35) {
        // Elevated ML score but no hard block
        showBadge(
          "flagged",
          `Elevated risk · ${Math.round(result.threat_score * 100)}%`,
          result.reason || "",
          6000
        );
      } else {
        // Clean
        showBadge("safe", "SecureLLM · Safe", null, 2500);
      }
    } catch (err) {
      showBadge("error", "SecureLLM error", "Flask server not running", 5000);
      console.error("[SecureLLM]", err);
    } finally {
      pendingScan = false;
    }
  }

  // ─────────────────────────────────────────────────────────────
  // 7. Intercept send — keyboard (Enter) and button click
  // ─────────────────────────────────────────────────────────────
  function attachSendListeners() {
    // Intercept Enter key on input fields
    const inputSels = SELECTORS[SITE]?.input || [];
    for (const sel of inputSels) {
      const el = document.querySelector(sel);
      if (el) {
        el.addEventListener("keydown", e => {
          if (e.key === "Enter" && !e.shiftKey) {
            screenAndNotify();
          }
        }, true);
      }
    }

    // Intercept send button click
    const sendSels = SELECTORS[SITE]?.send || [];
    for (const sel of sendSels) {
      const btn = document.querySelector(sel);
      if (btn) {
        btn.addEventListener("click", screenAndNotify, true);
      }
    }
  }

  // ─────────────────────────────────────────────────────────────
  // 8. MutationObserver — re-attach on DOM changes (SPA navigation)
  // ─────────────────────────────────────────────────────────────
  let lastPath = location.href;
  let attachDebounce = null;

  function tryAttach() {
    clearTimeout(attachDebounce);
    attachDebounce = setTimeout(() => {
      attachSendListeners();
    }, 600);
  }

  const observer = new MutationObserver(() => {
    if (location.href !== lastPath) {
      lastPath = location.href;
      tryAttach();
    }
    tryAttach();
  });

  observer.observe(document.body, { childList: true, subtree: true });

  // Initial attach
  if (document.readyState === "complete") {
    tryAttach();
  } else {
    window.addEventListener("load", tryAttach);
  }

  // Show site badge on load
  setTimeout(() => {
    const siteLabel = { chatgpt: "ChatGPT", gemini: "Gemini", claude: "Claude" }[SITE];
    showBadge("safe", `SecureLLM active on ${siteLabel}`, null, 2500);
  }, 1200);

})();
