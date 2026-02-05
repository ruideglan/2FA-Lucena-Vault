// Define o comportamento inicial ao instalar/atualizar
chrome.runtime.onInstalled.addListener(async () => {
  // Padrão: Abrir no Painel Lateral (false = Popup)
  await chrome.storage.local.set({ useSidePanel: false });
  await chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: false });
});

// Listener para mudanças na configuração vindas do popup.js
chrome.storage.onChanged.addListener((changes, namespace) => {
  if (namespace === "local" && changes.useSidePanel) {
    const useSidePanel = changes.useSidePanel.newValue;
    // Define se o clique no ícone abre o painel lateral (true) ou o popup padrão (false)
    chrome.sidePanel
      .setPanelBehavior({ openPanelOnActionClick: useSidePanel })
      .catch((err) => console.error("Erro ao alterar modo:", err));
  }
});
