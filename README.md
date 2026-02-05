# 2FA Lucena Vault - Chrome Extension 🛡️

**Um autenticador de dois fatores (TOTP) seguro, moderno e sincronizado para o seu navegador.**

O **2FA Lucena Vault** é uma extensão para Google Chrome que permite gerenciar seus códigos de autenticação de dois fatores (2FA) diretamente no navegador, sem depender do celular o tempo todo. Com foco em privacidade, design limpo e sincronização via conta Google.

<h3 align="Left">Interface Preview</h3>

<table align="Left" cellpadding="10">
  <tr>
    <th>Popup</th>
    <th>Painel Lateral</th>
    <th>Painel Lateral - Config</th>
  </tr>
  <tr>
    <td align="Left">
      <img src="https://i.ibb.co/tprvDyyZ/Captura-de-tela-2025-12-13-121001.png" height="500">
    </td>
    <td align="Left">
      <img src="https://i.ibb.co/nVXDdxK/Captura-de-tela-2025-12-13-121027.png" height="500">
    </td>
    <td align="Left">
      <img src="https://i.ibb.co/jvh3DH5q/Captura-de-tela-2025-12-13-121112.png" height="500">
    </td>
  </tr>
</table>
<br clear="both">

## ✨ Funcionalidades Principais

### 🔐 Segurança em Primeiro Lugar

- **Bloqueio por PIN:** Proteja seus códigos com um PIN de 4 dígitos.
- **Auto-Lock:** Bloqueio automático por inatividade (configurável de 1 minuto a 1 hora).
- **Modo Discreto:** Oculte/Desfoque os códigos visualmente para evitar olhares curiosos.
- **Criptografia:** Backups podem ser protegidos com senha (AES-GCM).

### ☁️ Sincronização e Backup

- **Cloud Sync:** Sincronize seus tokens entre computadores usando sua conta Google (Chrome Storage Sync).
- **Importação Inteligente:** Suporte a arquivos JSON, `.2fas` e Texto.
- **Exportação:** Exporte seus dados a qualquer momento (texto plano ou criptografado).

### 🎨 Personalização e UI

- **Modos de Visualização:** Escolha entre **Popup** (janela flutuante) ou **Painel Lateral** (Side Panel).
- **Ícones Personalizados:** Detecção automática de ícones, uso de URL ou upload de imagem própria.
- **Temas:** Suporte nativo a **Dark Mode** e Light Mode.
- **Organização:** Sistema de pastas para agrupar contas (ex: Pessoal, Trabalho).

---

## 🚀 Como Instalar (Modo Desenvolvedor)

Como esta extensão é Open Source, você pode instalá-la manualmente:

1.  **Baixe o código:** Clone este repositório ou baixe o ZIP.
2.  Abra o Chrome e vá para `chrome://extensions/`.
3.  No canto superior direito, ative o **"Modo do desenvolvedor"**.
4.  Clique em **"Carregar sem compactação"** (Load Unpacked).
5.  Selecione a pasta onde você salvou os arquivos deste projeto.
6.  Pronto! A extensão aparecerá na sua barra de tarefas.

---

## 📖 Guia de Uso (Tutorial)

### 1. Adicionando uma Conta (Token)

Existem duas formas de adicionar uma nova conta:

- **Escanear QR Code:** Clique no botão `+`, selecione "Escanear QR Code". A extensão tentará encontrar um QR Code visível na aba atual do navegador.
- **Manual:** Digite a "Chave Secreta" (fornecida pelo site, ex: `JBSWY3DPEHPK3PXP`) e defina um nome e ícone.

### 2. Organizando com Pastas

Mantenha tudo organizado:

1.  Vá em **Configurações** (ícone de engrenagem).
2.  Em "Gerenciar Pastas", clique em **+ Nova Pasta**.
3.  Para mover um token, clique no ícone de lápis (editar) no token e selecione a pasta desejada.
4.  Na tela inicial, você pode colapsar/expandir pastas para economizar espaço.

### 3. Sincronização na Nuvem

Para acessar seus códigos em outro computador:

1.  Vá em **Configurações**.
2.  Ative a opção **"Sincronizar (Chrome)"**.
3.  Faça o mesmo no outro computador. Seus dados serão mesclados automaticamente usando a infraestrutura segura do Google.

### 4. Segurança e Backup

- **Definir PIN:** Recomendado! Vá em Configurações > Segurança e crie um PIN. Isso impede que alguém use seus códigos se você deixar o PC desbloqueado.
- **Fazer Backup:** Vá em Configurações > Ações Rápidas > **Exportar Backup**. Guarde o arquivo gerado em um local seguro.

---

## 🛠️ Tecnologias Utilizadas

Este projeto foi construído utilizando tecnologias Web padrão, garantindo leveza e auditabilidade:

- **HTML5 / CSS3 (Variáveis CSS)** - Para interface responsiva e temas.
- **Vanilla JavaScript (ES6+)** - Lógica leve, sem frameworks pesados.
- **Chrome Extension API (Manifest V3)** - Padrão mais recente e seguro de extensões.
- **OTPAuth Library** - Para geração dos algoritmos TOTP.

## 🔒 Privacidade

- **Offline First:** Todos os dados são armazenados localmente no seu navegador (`chrome.storage.local`).
- **Zero Tracking:** A extensão não possui analytics, rastreadores ou envia dados para servidores de terceiros.
- **Sincronização:** Se ativada, os dados trafegam exclusivamente entre o seu navegador e os servidores do Google (Google Sync), criptografados pela sua conta Google.

---

## 📄 Licença

Este projeto está licenciado sob a licença [MIT](LICENSE). Sinta-se livre para estudar, modificar e distribuir.

---

Feito por **Ruideglan Lucena** e Google Gemini.
