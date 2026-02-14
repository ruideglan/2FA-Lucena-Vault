// --- Estado Global ---
let vaultItems = [];
let folders = [];
let customServices = [];
let vaultPinHash = null;
let autoLockTime = 0;
let lastUnlockTime = 0;
let updateInterval = null;
let isReorderMode = false;
let selectedIndex = -1;
let useCloudSync = false;
const UNCLASSIFIED_ID = "unclassified";
const SIMPLES_ICONS_BASE = "https://cdn.simpleicons.org/";

// Variaveis Temporárias (Importação)
let pendingImportData = null;

// Estado temporário para Editor de Ícones
let currentIconType = "auto"; // 'auto', 'url', 'custom'
let currentIconCustomBase64 = null;

document.addEventListener("DOMContentLoaded", async () => {
  // 1. Detecção Inteligente de Visualização
  const isPopupView = chrome.extension
    .getViews({ type: "popup" })
    .includes(window);

  // Ativa modo Compacto APENAS se for Popup.
  if (isPopupView) {
    document.body.classList.add("compact-mode");
  }

  // Carrega dados do Storage
  const data = await chrome.storage.local.get([
    "vaultItems",
    "folders",
    "customServices",
    "useSidePanel",
    "vaultPinHash",
    "autoLockTime",
    "lastUnlockTime",
    "theme",
    "useCloudSync",
  ]);

  vaultItems = Array.isArray(data.vaultItems) ? data.vaultItems : [];
  folders = Array.isArray(data.folders) ? data.folders : [];
  customServices = Array.isArray(data.customServices) ? data.customServices : [];
  vaultPinHash = data.vaultPinHash || null;
  autoLockTime = data.autoLockTime || 0;
  lastUnlockTime = data.lastUnlockTime || 0;
  useCloudSync = data.useCloudSync || false;

  // Aplica Tema Escuro se necessário
  if (data.theme === "dark") {
    document.documentElement.classList.add("dark");
    document.getElementById("iconMoon").classList.add("hidden");
    document.getElementById("iconSun").classList.remove("hidden");
  }

  // Configura UI de Auto-Lock
  const lockSelect = document.getElementById("autoLockSelect");
  if (lockSelect) lockSelect.value = autoLockTime;

  // Configura UI de Sync
  const toggleCloud = document.getElementById("toggleCloudSync");
  if(toggleCloud) toggleCloud.checked = useCloudSync;
  updateSyncStatusUI(false);

  // Lógica de Bloqueio na Abertura
  const now = Date.now();
  const isSessionExpired = now - lastUnlockTime > autoLockTime;
  const shouldLock = vaultPinHash && (autoLockTime === 0 || isSessionExpired);

  if (shouldLock) {
    document.getElementById("lock-screen").classList.add("active");
    document.getElementById("lockPinInput").focus();
  } else {
    if (vaultPinHash) updateActivity();
    initApp(data);
  }

  // Inicializa Sincronização em Nuvem (Listener)
  setupCloudSyncListener();

  // Inicializa Eventos
  bindEvents();
  bindLockEvents();
  bindCryptoEvents();
  bindKeyboardEvents();
  setupInactivityTracking();
});

function initApp(data) {
  const toggle = document.getElementById("toggleSidePanel");
  if (toggle) toggle.checked = data.useSidePanel === true;

  if (vaultItems.length === 0)
    document.getElementById("emptyState").classList.remove("hidden");

  updatePinConfigUI();
  startClock();
  renderCodesView();

  if (useCloudSync) {
    syncFromCloudToLocal();
  }
}

// ======================================================
// 0. SINCRONIZAÇÃO EM NUVEM (CHROME SYNC)
// ======================================================

function setupCloudSyncListener() {
  chrome.storage.onChanged.addListener((changes, namespace) => {
    // Se a mudança veio da nuvem (outro dispositivo)
    if (namespace === "sync" && useCloudSync) {
      console.log("Detectada alteração na nuvem...");
      if (changes.vaultItems) vaultItems = changes.vaultItems.newValue || [];
      if (changes.folders) folders = changes.folders.newValue || [];

      // Salva no local para persistir
      chrome.storage.local.set({ vaultItems, folders });

      updateSyncStatusUI(true, "Sincronizado via Nuvem");
      renderCodesView();
      renderConfigView();
    }
  });
}

async function syncLocalToCloud() {
  if (!useCloudSync) return;

  updateSyncStatusUI(false, "Sincronizando...");

  try {
    await chrome.storage.sync.set({
      vaultItems: vaultItems,
      folders: folders,
      lastSynced: Date.now(),
    });
    updateSyncStatusUI(true, "Sincronizado");
  } catch (e) {
    console.error("Erro ao sincronizar nuvem:", e);
    if (e.message && e.message.includes("QUOTA_BYTES")) {
      updateSyncStatusUI(false, "Erro: Limite da Nuvem Excedido");
      showAlert(
        "Erro de Sincronização",
        "O espaço gratuito de sincronização do Google (100KB) foi excedido. Alguns dados não foram salvos na nuvem.",
        "☁️",
      );
    } else {
      updateSyncStatusUI(false, "Erro na Sincronização");
    }
  }
}

async function syncFromCloudToLocal() {
  if (!useCloudSync) return;

  try {
    const cloudData = await chrome.storage.sync.get([
      "vaultItems",
      "folders",
      "lastSynced",
    ]);
    if (cloudData.lastSynced) {
      if (cloudData.vaultItems && cloudData.vaultItems.length > 0) {
        vaultItems = cloudData.vaultItems;
      }
      if (cloudData.folders) {
        folders = cloudData.folders;
      }
      await chrome.storage.local.set({ vaultItems, folders });
      renderCodesView();
      updateSyncStatusUI(true, "Atualizado da Nuvem");
    }
  } catch (e) {
    console.error("Erro ao baixar da nuvem:", e);
  }
}

function updateSyncStatusUI(success, msg) {
  const el = document.getElementById("sync-status-indicator");
  if (!el) return;

  if (msg) {
    el.innerText = msg;
    el.classList.toggle("sync-active", success);
  } else if (useCloudSync) {
    el.innerText = "Ativo";
    el.classList.add("sync-active");
  } else {
    el.innerText = "";
    el.classList.remove("sync-active");
  }
}

// ======================================================
// 1. SEGURANÇA E AUTO-LOCK
// ======================================================

function setupInactivityTracking() {
  ["mousemove", "mousedown", "keydown", "touchstart"].forEach((evt) => {
    document.addEventListener(evt, () => {
      if (
        !document.getElementById("lock-screen").classList.contains("active") &&
        vaultPinHash
      ) {
        updateActivity();
      }
    });
  });

  setInterval(() => {
    if (!vaultPinHash) return;
    if (document.getElementById("lock-screen").classList.contains("active"))
      return;
    if (autoLockTime === 0) return; // Imediato só bloqueia ao fechar

    const now = Date.now();
    if (now - lastUnlockTime > autoLockTime) {
      lockApp();
    }
  }, 1000);
}

async function updateActivity() {
  lastUnlockTime = Date.now();
  await chrome.storage.local.set({ lastUnlockTime });
}

function lockApp() {
  document.getElementById("lock-screen").classList.add("active");
  document.getElementById("lockPinInput").value = "";
  document.getElementById("lockPinInput").focus();
}

async function sha256(message) {
  const msgBuffer = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest("SHA-256", msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

function bindLockEvents() {
  const lockInput = document.getElementById("lockPinInput");
  const unlockBtn = document.getElementById("btnUnlock");

  unlockBtn.addEventListener("click", attemptUnlock);
  lockInput.addEventListener("keyup", async (e) => {
    if (e.key === "Enter") attemptUnlock();
    if (lockInput.value.length === 4) attemptUnlock();
  });
}

async function attemptUnlock() {
  const input = document.getElementById("lockPinInput");
  const val = input.value;

  if (val.length < 4) return;

  const hashedInput = await sha256(val);

  if (hashedInput === vaultPinHash) {
    document.getElementById("lock-screen").classList.remove("active");
    await updateActivity();
    const data = await chrome.storage.local.get(["useSidePanel"]);
    initApp(data);
  } else {
    input.classList.add("error");
    input.value = "";
    setTimeout(() => input.classList.remove("error"), 400);
  }
}

// ======================================================
// 2. CRIPTOGRAFIA DE BACKUP (AES-GCM)
// ======================================================

async function generateKey(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await window.crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveKey"],
  );
  return window.crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: salt, iterations: 100000, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"],
  );
}

async function encryptData(plainText, password) {
  const salt = window.crypto.getRandomValues(new Uint8Array(16));
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const key = await generateKey(password, salt);
  const enc = new TextEncoder();

  const encrypted = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    key,
    enc.encode(plainText),
  );

  return {
    encrypted: true,
    salt: btoa(String.fromCharCode(...salt)),
    iv: btoa(String.fromCharCode(...iv)),
    data: btoa(String.fromCharCode(...new Uint8Array(encrypted))),
  };
}

async function decryptData(encryptedObj, password) {
  try {
    const salt = Uint8Array.from(atob(encryptedObj.salt), (c) =>
      c.charCodeAt(0),
    );
    const iv = Uint8Array.from(atob(encryptedObj.iv), (c) => c.charCodeAt(0));
    const data = Uint8Array.from(atob(encryptedObj.data), (c) =>
      c.charCodeAt(0),
    );

    const key = await generateKey(password, salt);
    const decrypted = await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv },
      key,
      data,
    );

    const dec = new TextDecoder();
    return dec.decode(decrypted);
  } catch (e) {
    throw new Error("Senha incorreta ou arquivo corrompido.");
  }
}

function bindCryptoEvents() {
  // Exportação
  document.getElementById("btnExport").addEventListener("click", () => {
    document.getElementById("encrypt-inputs").classList.add("hidden");
    document.getElementById("btnEncryptToggle").classList.remove("hidden");
    document.getElementById("btnEncryptConfirm").style.display = "none";
    document.getElementById("btnEncryptSkip").style.display = "block";
    document.getElementById("encryptPass").value = "";
    document.getElementById("encryptPassConfirm").value = "";
    document.getElementById("encrypt-modal").classList.add("active");
  });

  document.getElementById("btnEncryptToggle").addEventListener("click", () => {
    document.getElementById("encrypt-inputs").classList.remove("hidden");
    document.getElementById("btnEncryptToggle").classList.add("hidden");
    document.getElementById("btnEncryptSkip").style.display = "none";
    document.getElementById("btnEncryptConfirm").style.display = "block";
    document.getElementById("encryptPass").focus();
  });

  document.getElementById("btnEncryptCancel").addEventListener("click", () => {
    document.getElementById("encrypt-modal").classList.remove("active");
  });

  document.getElementById("btnEncryptSkip").addEventListener("click", () => {
    performExport(null);
    document.getElementById("encrypt-modal").classList.remove("active");
  });

  document.getElementById("btnEncryptConfirm").addEventListener("click", () => {
    const p1 = document.getElementById("encryptPass").value;
    const p2 = document.getElementById("encryptPassConfirm").value;
    if (!p1 || p1 !== p2) {
      showAlert("Erro", "As senhas não conferem ou estão vazias.", "⚠️");
      return;
    }
    performExport(p1);
    document.getElementById("encrypt-modal").classList.remove("active");
  });

  // Importação (Descriptografar)
  document.getElementById("btnDecryptCancel").addEventListener("click", () => {
    document.getElementById("decrypt-modal").classList.remove("active");
    document.getElementById("fileInput").value = "";
    pendingImportData = null;
  });

  document
    .getElementById("btnDecryptConfirm")
    .addEventListener("click", async () => {
      const pass = document.getElementById("decryptPass").value;
      if (!pass) return;

      try {
        const jsonStr = await decryptData(pendingImportData, pass);
        const json = JSON.parse(jsonStr);
        detectAndImport(json);
        document.getElementById("decrypt-modal").classList.remove("active");
      } catch (e) {
        showAlert("Erro", "Senha incorreta.", "❌");
      }
    });
}

async function performExport(password) {
  const data = {
    vaultItems: vaultItems,
    folders: folders,
    customServices: customServices,
    vaultPinHash: vaultPinHash,
    autoLockTime: autoLockTime,
    exportedAt: new Date().toISOString(),
    app: "2FA Lucena Vault",
  };

  let finalData = JSON.stringify(data, null, 2);
  let filename = `backup-2fa-lucena-${Date.now()}.json`;

  if (password) {
    const encryptedObj = await encryptData(finalData, password);
    finalData = JSON.stringify(encryptedObj, null, 2);
  }

  const blob = new Blob([finalData], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// ======================================================
// 3. LEITURA DE QR CODE
// ======================================================

async function scanScreen() {
  if ("BarcodeDetector" in window) {
    try {
      const tabs = await chrome.tabs.query({
        active: true,
        currentWindow: true,
      });
      if (!tabs.length) return;

      const dataUrl = await chrome.tabs.captureVisibleTab(null, {
        format: "png",
      });

      const img = new Image();
      img.src = dataUrl;
      await new Promise((r) => (img.onload = r));

      const detector = new BarcodeDetector({ formats: ["qr_code"] });
      const barcodes = await detector.detect(img);

      if (!barcodes || barcodes.length === 0) {
        showAlert("Aviso", "Nenhum QR Code encontrado na tela.", "⚠️");
        return;
      }

      processScannedUrl(barcodes[0].rawValue);
      return; 
    } catch (e) {
      console.warn("Scan nativo falhou, tentando fallback...", e);
    }
  }

  showAlert(
    "Recurso Experimental",
    "A leitura nativa de QR Code falhou.\n\nPara ativar, acesse chrome://flags e habilite 'Experimental Web Platform features'.",
    "❌",
  );
}

function processScannedUrl(rawValue) {
  if (!rawValue.startsWith("otpauth://")) {
    showAlert("Erro", "QR Code inválido (não é otpauth).", "❌");
    return;
  }

  const url = new URL(rawValue);
  const secret = url.searchParams.get("secret");
  const issuerParam = url.searchParams.get("issuer");

  let label = decodeURIComponent(url.pathname.replace(/^\/\w+\//, ""));
  let account = label;
  let issuer = issuerParam || "";

  if (label.includes(":")) {
    const parts = label.split(":");
    if (!issuer) issuer = parts[0];
    account = parts[1];
  }

  if (!secret) {
    showAlert("Erro", "QR Code sem segredo.", "❌");
    return;
  }

  document.getElementById("manualIssuer").value = issuer;
  document.getElementById("manualAccount").value = account;
  document.getElementById("manualIconIssuer").value = issuer;
  document.getElementById("manualSecret").value = secret;
  
  // Reset icon state for clean manual entry
  currentIconCustomBase64 = null;
  setEditIconType("auto");

  document.getElementById("add-method-modal").classList.remove("active");
  document.getElementById("manual-add-modal").classList.add("active");
}

// ======================================================
// 4. MODO POP-OUT & NAVEGAÇÃO
// ======================================================

function openPopout() {
  if (chrome.extension.getViews({ type: "popup" }).length === 0) {
    chrome.windows.create({
      url: "popup.html",
      type: "popup",
      width: 375,
      height: 900,
    });
  } else {
    window.close();
    chrome.windows.create({
      url: "popup.html",
      type: "popup",
      width: 375,
      height: 900,
    });
  }
}

function bindKeyboardEvents() {
  document.addEventListener("keydown", (e) => {
    if (document.querySelector(".modal.active") && e.key !== "Escape") return;

    if (
      (e.key === "/" || (e.ctrlKey && e.key === "f")) &&
      document.activeElement !== document.getElementById("searchInput")
    ) {
      e.preventDefault();
      document.getElementById("searchInput").focus();
      return;
    }

    if (e.key === "ArrowDown") {
      e.preventDefault();
      moveSelection(1);
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      moveSelection(-1);
    } else if (e.key === "Enter") {
      if (selectedIndex !== -1) {
        const cards = getVisibleCards();
        if (cards[selectedIndex]) copyToken(cards[selectedIndex]);
      }
    } else if (e.key === "Escape") {
      const activeModal = document.querySelector(".modal.active");
      if (activeModal) {
        activeModal.classList.remove("active");
      } else if (
        document.activeElement === document.getElementById("searchInput")
      ) {
        document.getElementById("searchInput").blur();
      } else if (document.getElementById("searchInput").value) {
        document.getElementById("searchInput").value = "";
        document.getElementById("searchWrapper").classList.remove("active");
        renderCodesView();
      } else {
        selectedIndex = -1;
        updateSelectionVisuals();
      }
    }
  });
}

function getVisibleCards() {
  return Array.from(document.querySelectorAll(".token-card:not(.hidden)"));
}

function moveSelection(direction) {
  const cards = getVisibleCards();
  if (cards.length === 0) return;

  selectedIndex += direction;

  if (selectedIndex < 0) selectedIndex = cards.length - 1;
  if (selectedIndex >= cards.length) selectedIndex = 0;

  updateSelectionVisuals(cards);
}

function updateSelectionVisuals(cards = getVisibleCards()) {
  cards.forEach((c) => c.classList.remove("key-active"));

  if (selectedIndex !== -1 && cards[selectedIndex]) {
    const activeCard = cards[selectedIndex];
    activeCard.classList.add("key-active");
    activeCard.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }
}

// ======================================================
// 6. EVENTOS GERAIS DA UI
// ======================================================

function bindEvents() {
  const btnPopOut = document.getElementById("btnPopOut");
  if (btnPopOut) btnPopOut.addEventListener("click", openPopout);

  const btnHomeAdd = document.getElementById("btnHomeAdd");
  if (btnHomeAdd) {
    btnHomeAdd.addEventListener("click", () => {
      document.getElementById("add-method-modal").classList.add("active");
    });
  }

  document.getElementById("btnMethodScan").addEventListener("click", scanScreen);
  document.getElementById("btnMethodManual").addEventListener("click", () => {
    document.getElementById("manualIssuer").value = "";
    document.getElementById("manualAccount").value = "";
    document.getElementById("manualIconIssuer").value = "";
    document.getElementById("manualSecret").value = "";
    
    // Reset icon state
    currentIconCustomBase64 = null;
    setEditIconType("auto");

    document.getElementById("add-method-modal").classList.remove("active");
    document.getElementById("manual-add-modal").classList.add("active");
  });

  document.getElementById("btnMethodImport").addEventListener("click", () => {
    document.getElementById("add-method-modal").classList.remove("active");
    document.getElementById("modal-import-type").classList.add("active");
  });

  document.getElementById("btnCancelAddMethod").addEventListener("click", () => {
      document.getElementById("add-method-modal").classList.remove("active");
  });

  document.getElementById("btnImport").addEventListener("click", () => {
    document.getElementById("modal-import-type").classList.add("active");
  });

  document.getElementById("btnCancelImportType").addEventListener("click", () => {
      document.getElementById("modal-import-type").classList.remove("active");
  });

  document.getElementById("btnImport2FAS").addEventListener("click", () => {
    document.getElementById("modal-import-type").classList.remove("active");
    document.getElementById("fileInput").click();
  });

  document.getElementById("btnImportOther").addEventListener("click", () => {
    document.getElementById("modal-import-type").classList.remove("active");
    document.getElementById("fileInput").click();
  });

  // Icon Customization
  document.querySelectorAll(".icon-type-option").forEach((opt) => {
    opt.addEventListener("click", (e) => {
      const type = e.target.dataset.type;
      setEditIconType(type);
    });
  });

  document.getElementById("editTokenIconUrl").addEventListener("input", (e) => {
    document.getElementById("iconPreview").src = e.target.value || "icon.png";
  });
  
  // Also bind manual URL input preview (optional, but good UX)
  const manualUrlInput = document.getElementById("manualIconUrl");
  if(manualUrlInput) {
      manualUrlInput.addEventListener("input", (e) => {
          document.getElementById("manualIconPreview").src = e.target.value || "icon.png";
      });
  }

  // Handle both file inputs (manual and edit)
  const handleIconUpload = async (e, previewId) => {
      const file = e.target.files[0];
      if (file) {
        try {
          const base64 = await resizeImage(file, 128, 128);
          currentIconCustomBase64 = base64;
          document.getElementById(previewId).src = base64;
        } catch (err) {
          showAlert("Erro", "Falha ao processar imagem.", "❌");
        }
      }
  };

  document.getElementById("iconFileInput").addEventListener("change", (e) => handleIconUpload(e, "iconPreview"));
  document.getElementById("manualIconFile").addEventListener("change", (e) => handleIconUpload(e, "manualIconPreview"));

  // Theme
  const btnTheme = document.getElementById("btnToggleTheme");
  if (btnTheme) {
    btnTheme.addEventListener("click", async () => {
      const isDark = document.documentElement.classList.toggle("dark");
      document.getElementById("iconMoon").classList.toggle("hidden", isDark);
      document.getElementById("iconSun").classList.toggle("hidden", !isDark);
      await chrome.storage.local.set({ theme: isDark ? "dark" : "light" });
    });
  }

  // Reorder
  const btnReorder = document.getElementById("btnToggleReorder");
  if (btnReorder) {
    btnReorder.addEventListener("click", () => {
      isReorderMode = !isReorderMode;
      btnReorder.classList.toggle("active", isReorderMode);
      document.body.classList.toggle("reorder-active", isReorderMode);
      renderCodesView();
    });
  }

  // Mask
  const btnMask = document.getElementById("btnToggleMask");
  if (btnMask) {
    btnMask.addEventListener("click", () => {
      document.body.classList.toggle("masked");
      document.getElementById("iconEyeOpen").classList.toggle("hidden");
      document.getElementById("iconEyeClosed").classList.toggle("hidden");
    });
  }

  // Collapse
  const btnCollapse = document.getElementById("btnCollapseAll");
  if (btnCollapse) {
    btnCollapse.addEventListener("click", toggleAllFolders);
  }

  // Cliques na lista
  document.getElementById("codes-list-container").addEventListener("click", (e) => {
      if (isReorderMode) return;

      const header = e.target.closest(".folder-header");
      if (header) {
        header.classList.toggle("closed");
        const content = document.getElementById(`folder-content-${header.dataset.id}`);
        if (content) content.classList.toggle("hidden");
        return;
      }

      const editBtn = e.target.closest(".btn-edit-card");
      if (editBtn) {
        e.stopPropagation();
        openTokenModal(editBtn.closest(".token-card").dataset.id);
        return;
      }

      const card = e.target.closest(".token-card");
      if (card) copyToken(card);
    });

  document.getElementById("fileInput").addEventListener("change", preProcessImport);
  document.getElementById("btnExport").addEventListener("click", exportData);
  document.getElementById("btnSortAlpha").addEventListener("click", sortVaultAlphabetically);

  document.getElementById("btnCloseManual").addEventListener("click", () =>
      document.getElementById("manual-add-modal").classList.remove("active"),
    );
  document.getElementById("btnSaveManual").addEventListener("click", executeManualAdd);

  document.getElementById("nav-codes").addEventListener("click", () => switchTab("codes"));
  document.getElementById("nav-config").addEventListener("click", () => switchTab("config"));

  document.getElementById("toggleSidePanel").addEventListener("change", async (e) => {
      const useSidePanel = e.target.checked;
      await chrome.storage.local.set({ useSidePanel });
  });

  document.getElementById("toggleCloudSync").addEventListener("change", async (e) => {
      useCloudSync = e.target.checked;
      await chrome.storage.local.set({ useCloudSync });
      updateSyncStatusUI(useCloudSync);
      if (useCloudSync) {
        syncLocalToCloud();
      }
  });

  document.getElementById("btnForceSync").addEventListener("click", async () => {
      if (!useCloudSync) {
        showAlert("Sync Desativado", "Ative a sincronização primeiro.", "ℹ️");
        return;
      }
      await syncLocalToCloud();
    });

  // Search
  const searchInput = document.getElementById("searchInput");
  const btnClear = document.getElementById("btnClearSearch");
  searchInput.addEventListener("input", () => {
    document.getElementById("searchWrapper").classList.toggle("active", !!searchInput.value);
    renderCodesView();
  });
  btnClear.addEventListener("click", () => {
    searchInput.value = "";
    document.getElementById("searchWrapper").classList.remove("active");
    renderCodesView();
  });

  // Actions
  document.getElementById("btnNewFolder").addEventListener("click", openNewFolderModal);
  document.getElementById("btnWipe").addEventListener("click", wipeData);

  // PIN
  document.getElementById("btnSetupPin").addEventListener("click", () => {
    document.getElementById("newPinInput").value = "";
    document.getElementById("confirmPinInput").value = "";
    document.getElementById("newPinInput").type = "password";
    document.getElementById("confirmPinInput").type = "password";
    document.getElementById("eyeNewOpen").classList.remove("hidden");
    document.getElementById("eyeNewClosed").classList.add("hidden");
    document.getElementById("pin-creation-modal").classList.add("active");
    setTimeout(() => document.getElementById("newPinInput").focus(), 100);
  });

  document.getElementById("btnCancelPinSetup").addEventListener("click", () =>
      document.getElementById("pin-creation-modal").classList.remove("active"),
    );
  document.getElementById("btnSavePin").addEventListener("click", executeSetPin);
  document.getElementById("btnRemovePin").addEventListener("click", executeRemovePin);

  document.getElementById("btnToggleNewPin").addEventListener("click", () => {
    const inp1 = document.getElementById("newPinInput");
    const inp2 = document.getElementById("confirmPinInput");
    const eyeOpen = document.getElementById("eyeNewOpen");
    const eyeClosed = document.getElementById("eyeNewClosed");
    const isPass = inp1.type === "password";
    inp1.type = isPass ? "text" : "password";
    inp2.type = isPass ? "text" : "password";
    eyeOpen.classList.toggle("hidden", !isPass);
    eyeClosed.classList.toggle("hidden", isPass);
  });

  document.getElementById("autoLockSelect").addEventListener("change", async (e) => {
      autoLockTime = parseInt(e.target.value);
      await chrome.storage.local.set({ autoLockTime });
      updateActivity();
    });

  // Folder Modals
  document.getElementById("btnCancelNewFolder").addEventListener("click", () =>
      document.getElementById("new-folder-modal").classList.remove("active"),
    );
  document.getElementById("btnSaveNewFolder").addEventListener("click", executeCreateFolder);

  document.getElementById("btnCloseFolder").addEventListener("click", closeFolderModal);
  document.getElementById("btnDeleteFolder").addEventListener("click", deleteCurrentFolder);
  document.getElementById("editFolderName").addEventListener("input", updateFolderName);
  document.getElementById("filterFolderItems").addEventListener("input", renderFolderChecklist);
  document.getElementById("btnToggleSelectAll").addEventListener("click", toggleSelectAllFolderItems);

  // Token Modal
  document.getElementById("btnCloseToken").addEventListener("click", () =>
      document.getElementById("token-modal").classList.remove("active"),
    );
  document.getElementById("btnSaveToken").addEventListener("click", saveTokenChanges);
  document.getElementById("btnDeleteToken").addEventListener("click", deleteToken);

  document.getElementById("folders-manage-list").addEventListener("click", (e) => {
      const item = e.target.closest(".folder-manage-item");
      if (item) openFolderModal(item.dataset.id);
    });

  if (chrome.tabs) {
    chrome.tabs.onActivated.addListener(renderCodesView);
    chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
      if (changeInfo.status === "complete" && tab.active) renderCodesView();
    });
  }
}

// ======================================================
// 7. IMPORTAÇÃO INTELIGENTE (CORRIGIDA)
// ======================================================

async function preProcessImport(e) {
  const file = e.target.files[0];
  if (!file) return;
  const reader = new FileReader();

  reader.onload = async (ev) => {
    try {
      const json = JSON.parse(ev.target.result);

      if (json.encrypted) {
        pendingImportData = json;
        document.getElementById("decryptPass").value = "";
        document.getElementById("decrypt-modal").classList.add("active");
        setTimeout(() => document.getElementById("decryptPass").focus(), 100);
        return;
      }

      detectAndImport(json);
    } catch (err) {
      console.error(err);
      showAlert("Erro", "Erro ao ler JSON.", "❌");
    }
  };
  reader.readAsText(file);
}

function detectAndImport(json) {
  let importedCount = 0;

  // Backup Próprio (2FA Lucena Vault)
  if (json.app === "2FA Lucena Vault" && Array.isArray(json.vaultItems)) {
    if(confirm("Restaurar backup completo? Isso irá substituir/mesclar os itens.")) {
         restoreBackup(json);
    }
    return;
  }
  // 2FAS Backup
  else if (json.services && Array.isArray(json.services) && json.groups) {
    importedCount = import2FAS(json);
  }
  // Genérico
  else {
    importedCount = importGeneric(json);
  }

  if (importedCount > 0) {
    saveData().then(() => {
      document.getElementById("emptyState").classList.add("hidden");
      switchTab("codes");
      renderCodesView();
      startClock();
      showAlert("Importação Concluída", `${importedCount} tokens importados com sucesso.`, "✅");
    });
  } else {
    showAlert("Aviso", "Nenhum token válido encontrado.", "⚠️");
  }
}

function import2FAS(data) {
  let count = 0;
  const existingSecrets = new Set(vaultItems.map((i) => i.secret));

  // Importar Grupos
  if (data.groups) {
    data.groups.forEach((g) => {
      const exists = folders.some((f) => f.id === g.id || f.name === g.name);
      if (!exists) {
        folders.push({ id: g.id, name: g.name });
      }
    });
  }

  // Importar Serviços
  if (data.services) {
    data.services.forEach((s) => {
      if (!s.secret) return;
      const cleanSecret = s.secret.replace(/\s/g, "").toUpperCase();
      if (cleanSecret.length < 8) return;

      if (!existingSecrets.has(cleanSecret)) {
        let targetFolder = UNCLASSIFIED_ID;
        if (s.groupId && folders.some((f) => f.id === s.groupId)) {
          targetFolder = s.groupId;
        }

        const serviceName = s.name || "Serviço";
        const accountName = (s.otp ? s.otp.account || s.otp.label : "") || "";
        const issuerName = (s.otp ? s.otp.issuer : "") || serviceName;
        // Sanitiza para ícone
        const cleanIssuer = issuerName.trim().replace(/\s/g, '');

        vaultItems.push({
          id: Math.random().toString(36).substr(2, 9),
          secret: cleanSecret,
          line1: serviceName,
          line2: accountName,
          issuer: cleanIssuer, // Ícone sem espaços
          folderId: targetFolder,
          iconType: "auto",
          iconValue: null,
        });
        existingSecrets.add(cleanSecret);
        count++;
      }
    });
  }
  return count;
}

function importGeneric(json) {
    let newItems = [];
    let rawList = Array.isArray(json) ? json : (json.vaultItems || json.items || json.services || json.tokens || []);
    const existingSecrets = new Set(vaultItems.map(i => i.secret));
    
    rawList.forEach(raw => {
        let secret = null;
        let urlIssuer = null;
        let urlAccount = null;

        // Tenta extrair de objeto JSON padrão
        if (typeof raw === 'object' && raw !== null) {
            secret = raw.secret || raw.key || (raw.otp ? raw.otp.secret : null);
        }

        // Se for string ou se não achou secret no objeto, tenta parsear como URL otpauth
        if ((!secret || typeof raw === 'string') && String(raw).trim().startsWith('otpauth://')) {
             try {
                 const u = new URL(typeof raw === 'string' ? raw : (raw.otpauth || ''));
                 if (!secret) secret = u.searchParams.get('secret');
                 
                 const label = decodeURIComponent(u.pathname.replace(/^\/\w+\//, ''));
                 if (label.includes(':')) {
                     const parts = label.split(':');
                     urlIssuer = parts[0].trim();
                     urlAccount = parts[1].trim();
                 } else {
                     urlAccount = label.trim();
                 }
                 const qIssuer = u.searchParams.get('issuer');
                 if (qIssuer) urlIssuer = qIssuer.trim();
             } catch(e){}
        }

        if (secret) {
             secret = secret.replace(/\s/g, '').toUpperCase();
             if(!existingSecrets.has(secret)){
                // Lógica de fallback
                let issuer = (raw.issuer) || (raw.service) || (raw.otp && raw.otp.issuer) || urlIssuer || 'Serviço';
                let account = (raw.label) || (raw.name) || (raw.account) || (raw.otp && raw.otp.account) || urlAccount || '';
                
                // Evita "undefined"
                if (!issuer || String(issuer) === 'undefined') issuer = 'Serviço';
                if (!account || String(account) === 'undefined') account = '';

                const cleanIssuer = String(issuer).trim().replace(/\s/g, '');

                newItems.push({
                    id: Math.random().toString(36).substr(2, 9),
                    secret: secret,
                    line1: issuer,  // Título (Com espaços)
                    line2: account, // Subtítulo
                    issuer: cleanIssuer, // Emissor (Sem espaços, p/ Ícone)
                    folderId: UNCLASSIFIED_ID,
                    iconType: 'auto'
                });
                existingSecrets.add(secret);
             }
        }
    });
    
    if(newItems.length > 0) {
        vaultItems = [...vaultItems, ...newItems];
        return newItems.length;
    }
    return 0;
}

async function restoreBackup(data) {
    if (Array.isArray(data.folders)) folders = data.folders; else folders = [];
    if (Array.isArray(data.customServices)) customServices = data.customServices; else customServices = [];
    
    if (Array.isArray(data.vaultItems)) {
        // Mapeia e corrige itens restaurados com cuidado para não sobrescrever dados válidos
        vaultItems = data.vaultItems.map(item => {
            // 1. Título (line1)
            let finalTitle = item.line1;
            // Se line1 inválido, tenta usar issuer
            if (!finalTitle || String(finalTitle) === 'undefined' || String(finalTitle).trim() === '') {
                finalTitle = item.issuer;
            }
            if (!finalTitle || String(finalTitle) === 'undefined' || String(finalTitle).trim() === '') {
                finalTitle = 'Serviço';
            }

            // 2. Emissor (issuer) - Para Ícone
            let finalIssuer = item.issuer;
            if (!finalIssuer || String(finalIssuer) === 'undefined' || String(finalIssuer).trim() === '') {
                finalIssuer = finalTitle;
            }
            
            // Sanitização do Emissor (remove espaços para ícones melhores)
            finalIssuer = String(finalIssuer || '').trim().replace(/\s/g, '');
            if (!finalIssuer) finalIssuer = 'Servico';

            // 3. Subtítulo (line2)
            let finalSubtitle = item.line2;
            if (!finalSubtitle || String(finalSubtitle) === 'undefined') {
                finalSubtitle = '';
            }

            // 4. Garante ID
            if(!item.id) item.id = Math.random().toString(36).substr(2, 9);

            // Aplica as correções no item
            item.line1 = finalTitle;
            item.line2 = finalSubtitle;
            item.issuer = finalIssuer;
            
            return item;
        });
    } else {
        vaultItems = [];
    }
    
    vaultPinHash = data.vaultPinHash || null;
    autoLockTime = data.autoLockTime || 0;

    await saveData();
    
    document.getElementById('fileInput').value = '';
    document.getElementById('emptyState').classList.add('hidden');
    switchTab('codes');
    
    const storageData = await chrome.storage.local.get(['useSidePanel', 'theme']);
    initApp(storageData);
    
    renderConfigView();
    
    showAlert("Restaurado", `Backup restaurado com sucesso.`, "✅");
}

// ======================================================
// 8. RENDERIZAÇÃO & LÓGICA PRINCIPAL
// ======================================================

function switchTab(tab) {
  document.querySelectorAll(".view-container").forEach((v) => v.classList.remove("active"));
  document.querySelectorAll(".nav-item").forEach((n) => n.classList.remove("active"));

  if (tab === "codes") {
    document.getElementById("view-codes").classList.add("active");
    document.getElementById("nav-codes").classList.add("active");
    renderCodesView();
  } else {
    document.getElementById("view-config").classList.add("active");
    document.getElementById("nav-config").classList.add("active");
    renderConfigView();
  }
}

async function renderCodesView() {
  const list = document.getElementById("codes-list");
  const suggestedDiv = document.getElementById("suggested-section");
  const query = document.getElementById("searchInput").value.toLowerCase();

  let visible = vaultItems;
  if (query) {
    visible = visible.filter((i) =>
      (i.line1 + " " + i.line2).toLowerCase().includes(query),
    );
  }

  selectedIndex = -1;

  if (vaultItems.length === 0) {
    list.innerHTML = "";
    return;
  }
  document.getElementById("emptyState").classList.add("hidden");

  // Sugestões inteligentes
  let suggestedItems = [];
  if (!query) {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab?.url && !tab.url.startsWith("chrome://")) {
        const hostname = new URL(tab.url).hostname.toLowerCase();
        suggestedItems = vaultItems
          .filter((i) => {
            const candidates = [i.issuer, i.line1];
            return candidates.some((c) => {
              if (!c) return false;
              const clean = c.toLowerCase().replace(/[^a-z0-9]/g, "");
              if (clean.length < 3) return false;
              return hostname.includes(clean);
            });
          })
          .slice(0, 2); 
      }
    } catch (e) {}
  }

  if (suggestedItems.length > 0 && !query) {
    const labelHtml = `<div class="suggested-label">Sugestão</div>`;
    const cardsHtml = suggestedItems
      .map((item) => {
        let cardHtml = createCard(item);
        return cardHtml.replace('class="token-card', 'class="token-card suggested');
      })
      .join("");

    suggestedDiv.innerHTML = `${labelHtml}<div class="suggested-items-container">${cardsHtml}</div>`;
    suggestedDiv.classList.remove("hidden");
  } else {
    suggestedDiv.classList.add("hidden");
    suggestedDiv.innerHTML = "";
  }

  const grouped = {};
  folders.forEach((f) => (grouped[f.id] = { name: f.name, items: [] }));
  grouped[UNCLASSIFIED_ID] = { name: "Não Classificados", items: [] };

  visible.forEach((item) => {
    const fid = item.folderId && grouped[item.folderId] ? item.folderId : UNCLASSIFIED_ID;
    grouped[fid].items.push(item);
  });

  let html = "";
  const folderIds = folders
    .map((f) => f.id)
    .sort((a, b) => grouped[a].name.localeCompare(grouped[b].name));
  folderIds.push(UNCLASSIFIED_ID);

  folderIds.forEach((fid) => {
    const group = grouped[fid];
    if (group.items.length === 0) return;

    html += `
        <div class="folder-section">
            <div class="folder-header" data-id="${fid}">
                <span class="folder-title">${group.name}</span>
                <svg class="folder-arrow" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"></polyline></svg>
            </div>
            <div class="folder-content" id="folder-content-${fid}">
                ${group.items.map((i) => createCard(i)).join("")}
            </div>
        </div>`;
  });

  list.innerHTML = html;

  if (isReorderMode) {
    attachDragListeners(list);
  }

  loadDynamicIcons();
  refreshTokens();
}

function getIconImgTag(issuer, iconType, iconValue) {
  if (iconType === "custom" && iconValue) {
    return `<img src="${iconValue}" class="service-img">`;
  }
  if (iconType === "url" && iconValue) {
    return `<img src="${iconValue}" class="service-img" onerror="this.src='icon.png'">`;
  }
  if (!issuer) return `<img src="icon.png" class="service-img">`;

  let name = issuer.trim().toLowerCase();
  // Limpa espaços no nome para URL
  const cleanName = name.replace(/\s+/g, "");
  // Assume .com como padrão se não houver domínio
  const domain = cleanName.includes(".") ? cleanName : `${cleanName}.com`;
  const remoteUrl = `https://t3.gstatic.com/faviconV2?client=SOCIAL&type=FAVICON&fallback_opts=TYPE,SIZE,URL&url=http://${domain}&size=64`;
  
  return `<img src="icon.png" data-src="${remoteUrl}" class="service-img">`;
}

function loadDynamicIcons() {
  const images = document.querySelectorAll("img[data-src]");
  images.forEach((img) => {
    const remoteUrl = img.getAttribute("data-src");
    if (!remoteUrl) return;
    const remote = new Image();
    remote.src = remoteUrl;
    remote.onload = () => { img.src = remoteUrl; };
  });
}

function createCard(item) {
  const draggableClass = isReorderMode ? "draggable-item" : "";
  let type = item.iconType || (item.isDirect ? "url" : "auto");
  let value = item.iconValue || (item.isDirect ? item.issuer : null);
  // Usa 'issuer' (sem espaços) para gerar o ícone, mas mostra 'line1' (título) no texto
  const imgTag = getIconImgTag(item.issuer, type, value);

  return `
    <div class="token-card ${draggableClass}" data-id="${item.id}" data-secret="${item.secret}">
        <div class="drag-handle">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="9" cy="12" r="1"></circle><circle cx="9" cy="5" r="1"></circle><circle cx="9" cy="19" r="1"></circle><circle cx="15" cy="12" r="1"></circle><circle cx="15" cy="5" r="1"></circle><circle cx="15" cy="19" r="1"></circle></svg>
        </div>

        <div class="card-top">
            <div class="card-icon-box">
                ${imgTag}
            </div>
            <div class="card-text">
                <div class="card-issuer">${item.line1 || "Serviço"}</div>
                <div class="card-account">${item.line2 || ""}</div>
            </div>
            <div class="card-timer-wrap">
                <div class="timer-box">
                    <svg class="timer-svg" viewBox="0 0 24 24">
                        <circle class="timer-circle" stroke-width="3" fill="transparent" r="9" cx="12" cy="12" 
                        style="stroke-dasharray: 56.55; stroke-dashoffset: 0;"></circle>
                    </svg>
                    <span class="timer-num">30</span>
                </div>
            </div>
        </div>

        <div class="card-separator"></div>

        <div class="card-bottom">
            <div class="card-code">... ...</div>
            <div class="card-next">
                <span class="lbl-next">Next</span>
                <span class="val-next">... ...</span>
            </div>
        </div>

        <div class="btn-edit-card" title="Editar">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg>
        </div>
    </div>`;
}

// --- Drag & Drop ---
function attachDragListeners(container) {
  const cards = container.querySelectorAll(".token-card");
  cards.forEach((card) => {
    const handle = card.querySelector(".drag-handle");
    if (handle) {
      handle.addEventListener("mousedown", () => card.setAttribute("draggable", "true"));
      handle.addEventListener("mouseup", () => card.setAttribute("draggable", "false"));
      handle.addEventListener("mouseleave", () =>
        setTimeout(() => { if (!card.classList.contains("dragging")) card.setAttribute("draggable", "false"); }, 100)
      );
    }
    card.addEventListener("dragstart", (e) => {
      card.classList.add("dragging");
      e.dataTransfer.effectAllowed = "move";
    });
    card.addEventListener("dragend", async () => {
      card.classList.remove("dragging");
      card.setAttribute("draggable", "false");
      const newOrderIds = Array.from(document.querySelectorAll(".token-card")).map((c) => c.dataset.id);
      const newItemList = [];
      newOrderIds.forEach((id) => {
        const item = vaultItems.find((i) => i.id === id);
        if (item) {
          const parentContent = document.querySelector(`.token-card[data-id="${id}"]`).closest(".folder-content");
          if (parentContent) {
            const folderSectionId = parentContent.id.replace("folder-content-", "");
            item.folderId = folderSectionId;
          }
          newItemList.push(item);
        }
      });
      if (!document.getElementById("searchInput").value) {
        vaultItems = newItemList;
        await saveData();
      }
    });
  });

  container.addEventListener("dragover", (e) => {
    e.preventDefault();
    const draggable = document.querySelector(".dragging");
    if (!draggable) return;
    const targetFolder = e.target.closest(".folder-content");
    if (!targetFolder) return;
    const afterElement = getDragAfterElement(targetFolder, e.clientX, e.clientY);
    if (afterElement == null) {
      targetFolder.appendChild(draggable);
    } else {
      targetFolder.insertBefore(draggable, afterElement);
    }
  });
}

function getDragAfterElement(container, x, y) {
  const draggableElements = [...container.querySelectorAll(".token-card:not(.dragging)")];
  return draggableElements.reduce(
    (closest, child) => {
      const box = child.getBoundingClientRect();
      const boxCenterX = box.left + box.width / 2;
      const boxCenterY = box.top + box.height / 2;
      const dist = Math.hypot(x - boxCenterX, y - boxCenterY);
      if (dist < closest.offset) {
        return { offset: dist, element: child };
      } else {
        return closest;
      }
    },
    { offset: Number.POSITIVE_INFINITY },
  ).element;
}

// --- Helper: Resize Image ---
function resizeImage(file, maxWidth, maxHeight) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = function (event) {
      const img = new Image();
      img.onload = function () {
        const canvas = document.createElement("canvas");
        let width = img.width;
        let height = img.height;
        if (width > height) {
          if (width > maxWidth) {
            height *= maxWidth / width;
            width = maxWidth;
          }
        } else {
          if (height > maxHeight) {
            width *= maxHeight / height;
            height = maxHeight;
          }
        }
        canvas.width = width;
        canvas.height = height;
        const ctx = canvas.getContext("2d");
        ctx.drawImage(img, 0, 0, width, height);
        resolve(canvas.toDataURL(file.type));
      };
      img.src = event.target.result;
    };
    reader.onerror = reject;
    reader.readAsDataURL(file);
  });
}

// --- Token Editor ---
function openTokenModal(id) {
  const item = vaultItems.find((i) => i.id === id);
  if (!item) return;
  document.getElementById("editTokenId").value = id;
  document.getElementById("editTokenTitle").value = item.line1;
  document.getElementById("editTokenSubtitle").value = item.line2;
  document.getElementById("editTokenIssuer").value = item.issuer;
  document.getElementById("editTokenSecret").value = item.secret;

  let type = item.iconType || (item.isDirect ? "url" : "auto");
  let value = item.iconValue || (item.isDirect ? item.issuer : null);

  setEditIconType(type);
  document.getElementById("editTokenIconUrl").value = type === "url" ? value : "";

  if (type === "custom" && value) {
    document.getElementById("iconPreview").src = value;
    currentIconCustomBase64 = value;
  } else if (type === "url" && value) {
    document.getElementById("iconPreview").src = value;
  } else {
    // Preview auto
    let imgTag = getIconImgTag(item.issuer, "auto", null);
    const match = imgTag.match(/src="([^"]+)"/);
    const dataMatch = imgTag.match(/data-src="([^"]+)"/);
    if (dataMatch && dataMatch[1]) {
      document.getElementById("iconPreview").src = dataMatch[1];
    } else if (match && match[1]) {
      document.getElementById("iconPreview").src = match[1];
    } else {
      document.getElementById("iconPreview").src = "icon.png";
    }
  }

  const folderSelect = document.getElementById("editTokenFolder");
  folderSelect.innerHTML = `<option value="${UNCLASSIFIED_ID}">Não Classificados</option>`;
  folders.forEach((f) => {
    const opt = document.createElement("option");
    opt.value = f.id;
    opt.innerText = f.name;
    if (item.folderId === f.id) opt.selected = true;
    folderSelect.appendChild(opt);
  });
  document.getElementById("token-modal").classList.add("active");
}

function setEditIconType(type) {
  currentIconType = type;
  
  // Atualiza visual dos botões (abas)
  document.querySelectorAll(".icon-type-option").forEach((opt) => {
    opt.classList.toggle("active", opt.dataset.type === type);
  });

  // Helper para mostrar/esconder elemento se ele existir
  const toggle = (id, show) => {
    const el = document.getElementById(id);
    if (el) el.classList.toggle("hidden", !show);
  };

  // Elementos do Modal de Edição (IDs únicos no HTML)
  toggle("iconInputAuto", type === "auto");
  toggle("editTokenIconInputUrl", type === "url");
  toggle("iconInputCustom", type === "custom");

  // Elementos do Modal de Adição Manual (IDs únicos no HTML)
  toggle("manualIconInputAuto", type === "auto");
  toggle("manualIconInputUrl", type === "url");
  toggle("manualIconInputCustom", type === "custom");
}

async function saveTokenChanges() {
  const id = document.getElementById("editTokenId").value;
  const item = vaultItems.find((i) => i.id === id);
  if (item) {
    item.line1 = document.getElementById("editTokenTitle").value;
    item.line2 = document.getElementById("editTokenSubtitle").value;
    item.issuer = document.getElementById("editTokenIssuer").value;
    item.secret = document.getElementById("editTokenSecret").value;
    item.folderId = document.getElementById("editTokenFolder").value;

    item.iconType = currentIconType;
    if (currentIconType === "url") {
      item.iconValue = document.getElementById("editTokenIconUrl").value;
    } else if (currentIconType === "custom") {
      if (currentIconCustomBase64) item.iconValue = currentIconCustomBase64;
    } else {
      item.iconValue = null;
    }

    await saveData();
    document.getElementById("token-modal").classList.remove("active");
    renderCodesView();
  }
}

async function deleteToken() {
  if (await showConfirm("Excluir Token", "Tem certeza?", true)) {
    const id = document.getElementById("editTokenId").value;
    vaultItems = vaultItems.filter((i) => i.id !== id);
    await saveData();
    document.getElementById("token-modal").classList.remove("active");
    renderCodesView();
  }
}

// --- Folder Management ---
function renderConfigView() {
  const list = document.getElementById("folders-manage-list");

  if (folders.length === 0) {
    list.innerHTML = '<div style="padding:20px; text-align:center; font-size:12px; color:var(--text-sub); background:var(--bg-input); border-radius:8px; border:1px dashed var(--border); margin-top:12px;">Nenhuma pasta criada.</div>';
  } else {
    list.innerHTML = `<div class="folder-manage-list">` +
      folders.map((f) => {
          const count = vaultItems.filter((i) => i.folderId === f.id).length;
          return `
          <div class="folder-manage-item" data-id="${f.id}">
              <div class="folder-info">
                  <span class="folder-name">${f.name}</span>
                  <span class="folder-count">${count} itens</span>
              </div>
              <svg class="folder-arrow-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"></polyline></svg>
          </div>`;
        }).join("") + `</div>`;
  }
  updatePinConfigUI();
}

function openNewFolderModal() {
  document.getElementById("newFolderNameInput").value = "";
  document.getElementById("new-folder-modal").classList.add("active");
  setTimeout(() => document.getElementById("newFolderNameInput").focus(), 100);
}

async function executeCreateFolder() {
  const name = document.getElementById("newFolderNameInput").value.trim();
  if (name) {
    const newId = "f_" + Date.now();
    folders.push({ id: newId, name });
    await saveData();
    renderConfigView();
    document.getElementById("new-folder-modal").classList.remove("active");
    openFolderModal(newId);
  } else {
    document.getElementById("newFolderNameInput").focus();
  }
}

async function wipeData() {
  if (await showConfirm("Apagar Tudo?", "Isso removerá todas as contas e pastas permanentemente.", true)) {
    vaultItems = [];
    folders = [];
    vaultPinHash = null;
    autoLockTime = 0;
    await chrome.storage.local.set({ vaultItems, folders, vaultPinHash, autoLockTime });
    if (useCloudSync) await chrome.storage.sync.clear();
    location.reload();
  }
}

let curFolderId = null;

function openFolderModal(fid) {
  const f = folders.find((x) => x.id === fid);
  if (!f) return;
  curFolderId = fid;
  document.getElementById("editFolderName").value = f.name;
  document.getElementById("filterFolderItems").value = "";
  document.getElementById("folder-modal").classList.add("active");
  renderFolderChecklist();
}

function renderFolderChecklist() {
  const list = document.getElementById("folder-items-checklist");
  const filter = document.getElementById("filterFolderItems").value.toLowerCase();
  const visible = vaultItems.filter((i) => {
      const matchText = (i.line1 + " " + i.line2).toLowerCase().includes(filter);
      const belongsHere = i.folderId === curFolderId;
      const isFree = !i.folderId || i.folderId === UNCLASSIFIED_ID;
      return matchText && (belongsHere || isFree);
    }).sort((a, b) => a.line1.localeCompare(b.line1));

  list.innerHTML = visible.map((item) => {
      const checked = item.folderId === curFolderId ? "checked" : "";
      return `
        <label class="check-item" style="display:flex; padding:8px; align-items:center;">
            <input type="checkbox" ${checked} data-tid="${item.id}" style="margin-right:10px;">
            <div style="flex:1">
                <div style="font-weight:600; font-size:13px;">${item.line1}</div>
                <div style="font-size:11px; color:#6B7280;">${item.line2}</div>
            </div>
        </label>`;
    }).join("");

  list.querySelectorAll("input").forEach((chk) => {
    chk.addEventListener("change", async (e) => {
      const item = vaultItems.find((i) => i.id === e.target.dataset.tid);
      if (item) {
        item.folderId = e.target.checked ? curFolderId : UNCLASSIFIED_ID;
        await saveData();
      }
    });
  });
}

async function toggleSelectAllFolderItems() {
  if (!curFolderId) return;
  const filter = document.getElementById("filterFolderItems").value.toLowerCase();
  const visibleItems = vaultItems.filter((i) => {
    const matchText = (i.line1 + " " + i.line2).toLowerCase().includes(filter);
    const belongsHere = i.folderId === curFolderId;
    const isFree = !i.folderId || i.folderId === UNCLASSIFIED_ID;
    return matchText && (belongsHere || isFree);
  });
  if (visibleItems.length === 0) return;
  const allSelected = visibleItems.every((i) => i.folderId === curFolderId);
  const newStatus = allSelected ? UNCLASSIFIED_ID : curFolderId;
  visibleItems.forEach((i) => (i.folderId = newStatus));
  await saveData();
  renderFolderChecklist();
}

function updateFolderName(e) {
  if (!curFolderId) return;
  const f = folders.find((x) => x.id === curFolderId);
  if (f) f.name = e.target.value;
}

function closeFolderModal() {
  saveData().then(() => {
    document.getElementById("folder-modal").classList.remove("active");
    curFolderId = null;
    renderConfigView();
  });
}

async function deleteCurrentFolder() {
  if (await showConfirm("Excluir Pasta?", "Os itens voltarão para 'Não Classificados'.", true)) {
    vaultItems.forEach((i) => {
      if (i.folderId === curFolderId) i.folderId = UNCLASSIFIED_ID;
    });
    folders = folders.filter((f) => f.id !== curFolderId);
    await saveData();
    closeFolderModal();
  }
}

// PIN
function updatePinConfigUI() {
  const noneDiv = document.getElementById("pin-status-none");
  const activeDiv = document.getElementById("pin-status-active");
  if (vaultPinHash) {
    noneDiv.classList.add("hidden");
    activeDiv.classList.remove("hidden");
  } else {
    noneDiv.classList.remove("hidden");
    activeDiv.classList.add("hidden");
  }
}

async function executeSetPin() {
  const input = document.getElementById("newPinInput");
  const confirm = document.getElementById("confirmPinInput");
  const val = input.value;
  if (!/^\d{4}$/.test(val)) {
    showAlert("Erro", "O PIN deve conter exatamente 4 números.", "⚠️");
    return;
  }
  if (val !== confirm.value) {
    showAlert("Erro", "Os PINs não conferem.", "⚠️");
    return;
  }
  const hash = await sha256(val);
  vaultPinHash = hash;
  lastUnlockTime = Date.now();
  await chrome.storage.local.set({ vaultPinHash, lastUnlockTime });
  updatePinConfigUI();
  document.getElementById("pin-creation-modal").classList.remove("active");
  input.value = "";
  confirm.value = "";
  showAlert("Sucesso", "PIN de segurança ativado.", "🔒");
}

async function executeRemovePin() {
  if (await showConfirm("Remover PIN", "Qualquer pessoa com acesso a este computador poderá ver seus códigos.", true)) {
    vaultPinHash = null;
    await chrome.storage.local.remove("vaultPinHash");
    updatePinConfigUI();
    showAlert("Aviso", "PIN de segurança removido.", "🔓");
  }
}

// Helper Gerais
function toggleAllFolders() {
  const headers = document.querySelectorAll(".folder-header");
  if (headers.length === 0) return;
  const anyOpen = Array.from(headers).some((h) => !h.classList.contains("closed"));
  headers.forEach((h) => {
    const content = document.getElementById(`folder-content-${h.dataset.id}`);
    if (anyOpen) {
      h.classList.add("closed");
      if (content) content.classList.add("hidden");
      document.getElementById("iconCollapse").classList.add("hidden");
      document.getElementById("iconExpand").classList.remove("hidden");
    } else {
      h.classList.remove("closed");
      if (content) content.classList.remove("hidden");
      document.getElementById("iconCollapse").classList.remove("hidden");
      document.getElementById("iconExpand").classList.add("hidden");
    }
  });
}

function sortVaultAlphabetically() {
  showConfirm("Ordenar A-Z?", "Isso reorganizará todos os seus tokens alfabeticamente.", false).then((yes) => {
    if (yes) {
      vaultItems.sort((a, b) => (a.line1 + a.line2).toLowerCase().localeCompare((b.line1 + b.line2).toLowerCase()));
      saveData().then(() => {
        renderCodesView();
        showAlert("Sucesso", "Tokens ordenados de A a Z.", "✅");
      });
    }
  });
}

function executeManualAdd() {
  const issuer = document.getElementById("manualIssuer").value.trim();
  const account = document.getElementById("manualAccount").value.trim();
  const iconIssuer = document.getElementById("manualIconIssuer").value.trim();
  let secret = document.getElementById("manualSecret").value.trim().replace(/\s/g, "").toUpperCase();

  if (!secret) return showAlert("Erro", "A Chave Secreta é obrigatória.", "⚠️");
  if (!/^[A-Z2-7=]+$/.test(secret)) return showAlert("Erro", "Chave Secreta inválida (use Base32).", "⚠️");
  if (vaultItems.some((i) => i.secret === secret)) return showAlert("Aviso", "Este token já existe.", "⚠️");

  // Icon handling
  let iconType = currentIconType;
  let iconValue = null;
  if (iconType === "url") iconValue = document.getElementById("manualIconUrl").value;
  if (iconType === "custom") iconValue = currentIconCustomBase64;

  // Sanitiza emissor para ícone
  const cleanIssuer = (iconIssuer || issuer || 'Serviço').replace(/\s/g, '');

  vaultItems.push({
    id: Math.random().toString(36).substr(2, 9),
    secret: secret,
    line1: issuer || "Sem Título",
    line2: account || "",
    issuer: cleanIssuer,
    folderId: UNCLASSIFIED_ID,
    iconType: iconType,
    iconValue: iconValue,
  });

  saveData().then(() => {
    document.getElementById("manual-add-modal").classList.remove("active");
    document.getElementById("emptyState").classList.add("hidden");
    switchTab("codes");
    renderCodesView();
    startClock();
    showAlert("Sucesso", "Token adicionado.", "✅");
  });
}

async function exportData() {
    performExport(null);
}

function showConfirm(title, message, isDestructive = false) {
  return new Promise((resolve) => {
    const modal = document.getElementById("confirm-modal");
    document.getElementById("confirmTitle").innerText = title;
    document.getElementById("confirmMessage").innerText = message;
    const btnOk = document.getElementById("btnConfirmOk");
    if (isDestructive) {
      btnOk.className = "btn-full btn-danger";
      btnOk.innerText = "Sim, Apagar";
    } else {
      btnOk.className = "btn-full btn-new-folder";
      btnOk.innerText = "Confirmar";
    }
    modal.classList.add("active");
    const cleanup = () => {
      modal.classList.remove("active");
      btnOk.removeEventListener("click", onOk);
      document.getElementById("btnConfirmCancel").removeEventListener("click", onCancel);
    };
    const onOk = () => { cleanup(); resolve(true); };
    const onCancel = () => { cleanup(); resolve(false); };
    btnOk.addEventListener("click", onOk);
    document.getElementById("btnConfirmCancel").addEventListener("click", onCancel);
  });
}

function showAlert(title, message, icon = "ℹ️") {
  const modal = document.getElementById("alert-modal");
  document.getElementById("alertTitle").innerText = title;
  document.getElementById("alertMessage").innerText = message;
  document.getElementById("alertIcon").innerText = icon;
  modal.classList.add("active");
  document.getElementById("btnAlertOk").onclick = () => modal.classList.remove("active");
}

async function saveData() {
  await chrome.storage.local.set({
    vaultItems,
    folders,
    vaultPinHash,
    autoLockTime,
    useCloudSync,
  });
  if (useCloudSync) {
    await syncLocalToCloud();
  }
}

function startClock() {
  if (updateInterval) clearInterval(updateInterval);
  refreshTokens();
  updateInterval = setInterval(refreshTokens, 1000);
}

function refreshTokens() {
  const epoch = Math.floor(Date.now() / 1000);
  const period = 30;
  const remaining = period - (epoch % period);
  const circ = 56.55;
  const offset = circ - (remaining / period) * circ;

  document.querySelectorAll(".token-card").forEach((card) => {
    const sec = card.dataset.secret;
    if (!sec) return;
    try {
      const totp = new OTPAuth.TOTP({
        algorithm: "SHA1",
        digits: 6,
        period: 30,
        secret: OTPAuth.Secret.fromBase32(sec),
      });
      const token = totp.generate();

      const el = card.querySelector(".card-code");
      if (el) {
        const fmt = token.slice(0, 3) + " " + token.slice(3);
        if (!el.classList.contains("copied")) el.innerText = fmt;
      }

      const ring = card.querySelector(".timer-circle");
      if (ring) ring.style.strokeDashoffset = offset;
      const num = card.querySelector(".timer-num");
      if (num) num.innerText = remaining;

      if (remaining <= 5) {
        card.classList.add("expiring");
        const next = totp.generate({ timestamp: (Math.floor(Date.now() / 1000 / 30) + 1) * 30 * 1000 });
        const nextEl = card.querySelector(".val-next");
        if (nextEl) nextEl.innerText = next.slice(0, 3) + " " + next.slice(3);
      } else {
        card.classList.remove("expiring");
        const nextEl = card.querySelector(".val-next");
        if (nextEl) nextEl.innerText = "";
      }
    } catch (e) {}
  });
}

function copyToken(card) {
  const el = card.querySelector(".card-code");
  const txt = el.innerText.replace(/\s/g, "");
  navigator.clipboard.writeText(txt).then(() => {
    el.classList.add("copied");
    const old = el.innerText;
    el.innerText = "COPIADO";
    setTimeout(() => {
      el.classList.remove("copied");
      el.innerText = old;
    }, 800);
  });
}