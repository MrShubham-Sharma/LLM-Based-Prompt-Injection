/**
 * SecureLLM Popup Script
 * Controls the extension settings panel.
 */

const $ = id => document.getElementById(id);

// ── Load saved settings ──────────────────────────────────────
chrome.storage.local.get(
  ["securellm_enabled", "securellm_threshold", "securellm_stats"],
  data => {
    const enabled   = data.securellm_enabled !== false; // default on
    const threshold = data.securellm_threshold ?? 0.5;
    const stats     = data.securellm_stats || { total: 0, flagged: 0, blocked: 0 };

    $("enable-toggle").checked  = enabled;
    $("toggle-label").textContent = enabled ? "On" : "Off";
    $("threshold-slider").value = threshold;
    $("threshold-val").textContent = threshold.toFixed(2);
    $("stat-total").textContent   = stats.total;
    $("stat-flagged").textContent = stats.flagged;
    $("stat-blocked").textContent = stats.blocked;
  }
);

// ── Highlight current active tab site ───────────────────────
chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
  const url = tabs[0]?.url || "";
  if (url.includes("chatgpt.com") || url.includes("openai.com")) {
    $("chip-chatgpt").classList.add("active");
  } else if (url.includes("gemini.google.com")) {
    $("chip-gemini").classList.add("active");
  } else if (url.includes("claude.ai")) {
    $("chip-claude").classList.add("active");
  }
});

// ── Check Flask server status ───────────────────────────────
async function checkServer() {
  try {
    const res = await fetch("http://127.0.0.1:5000/api/config", {
      method: "GET", signal: AbortSignal.timeout(2500)
    });
    if (res.ok) {
      $("status-dot").className  = "status-dot online";
      $("status-text").textContent = "Flask server connected";
    } else {
      throw new Error("bad status");
    }
  } catch {
    $("status-dot").className  = "status-dot offline";
    $("status-text").textContent = "Flask server offline — run: python app.py";
  }
}

checkServer();

// ── Toggle on/off ────────────────────────────────────────────
$("enable-toggle").addEventListener("change", e => {
  const enabled = e.target.checked;
  $("toggle-label").textContent = enabled ? "On" : "Off";
  chrome.storage.local.set({ securellm_enabled: enabled });

  // Tell all matching content scripts
  chrome.tabs.query({}, tabs => {
    tabs.forEach(tab => {
      try {
        chrome.tabs.sendMessage(tab.id, {
          type: "SETTINGS_UPDATED", enabled
        });
      } catch (_) {}
    });
  });
});

// ── Threshold slider ─────────────────────────────────────────
$("threshold-slider").addEventListener("input", e => {
  const val = parseFloat(e.target.value);
  $("threshold-val").textContent = val.toFixed(2);
  chrome.storage.local.set({ securellm_threshold: val });

  chrome.tabs.query({}, tabs => {
    tabs.forEach(tab => {
      try {
        chrome.tabs.sendMessage(tab.id, {
          type: "SETTINGS_UPDATED", threshold: val
        });
      } catch (_) {}
    });
  });
});

// ── Reset stats ──────────────────────────────────────────────
$("btn-reset").addEventListener("click", () => {
  const empty = { total: 0, flagged: 0, blocked: 0 };
  chrome.storage.local.set({ securellm_stats: empty });
  $("stat-total").textContent   = 0;
  $("stat-flagged").textContent = 0;
  $("stat-blocked").textContent = 0;
});

// ── Spatial UI 3D Tilt Animations ─────────────────────────────
document.querySelectorAll('.stat-box').forEach(el => {
  el.addEventListener('mousemove', e => {
    const rect = el.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    const centerX = rect.width / 2;
    const centerY = rect.height / 2;
    const rotateX = ((y - centerY) / centerY) * -15; // Max 15 deg tilt
    const rotateY = ((x - centerX) / centerX) * 15;
    
    el.style.transform = `perspective(800px) rotateX(${rotateX}deg) rotateY(${rotateY}deg) scale3d(1.05, 1.05, 1.05)`;
    el.style.transition = 'none';
  });
  
  el.addEventListener('mouseleave', () => {
    el.style.transform = 'perspective(800px) rotateX(0deg) rotateY(0deg) scale3d(1, 1, 1)';
    el.style.transition = 'transform 0.4s ease, background 0.2s ease, box-shadow 0.2s ease';
  });
});

// ── Threat Ripple Animation ──────────────────────────────────
chrome.storage.onChanged.addListener((changes, namespace) => {
  if (changes.securellm_stats) {
    const oldStats = changes.securellm_stats.oldValue || { blocked: 0 };
    const newStats = changes.securellm_stats.newValue || { blocked: 0 };
    if (newStats.blocked > oldStats.blocked) {
      triggerThreatRipple();
    }
  }
});

function triggerThreatRipple() {
  const ripple = document.createElement('div');
  ripple.className = 'threat-ripple-effect';
  document.body.appendChild(ripple);
  document.body.classList.add('threat-active');
  
  setTimeout(() => {
    if (ripple.parentNode) ripple.remove();
    document.body.classList.remove('threat-active');
  }, 800);
}
