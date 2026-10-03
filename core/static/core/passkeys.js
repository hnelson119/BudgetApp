"use strict";

const passkeyForm = document.querySelector("[data-passkey-registration]");

function decodeBase64Url(value) {
  const padding = "=".repeat((4 - (value.length % 4)) % 4);
  const binary = atob((value + padding).replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function encodeBase64Url(value) {
  const bytes = new Uint8Array(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function registrationCredentialToJSON(credential) {
  return {
    id: credential.id,
    rawId: encodeBase64Url(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment,
    clientExtensionResults: credential.getClientExtensionResults(),
    response: {
      attestationObject: encodeBase64Url(credential.response.attestationObject),
      clientDataJSON: encodeBase64Url(credential.response.clientDataJSON),
      transports: credential.response.getTransports ? credential.response.getTransports() : [],
    },
  };
}

if (passkeyForm) {
  passkeyForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const error = passkeyForm.querySelector("[data-passkey-error]");
    const button = passkeyForm.querySelector("button[type='submit']");
    const csrf = passkeyForm.querySelector("input[name='csrfmiddlewaretoken']").value;
    error.hidden = true;
    button.disabled = true;
    try {
      if (!window.PublicKeyCredential || !navigator.credentials) {
        throw new Error("This browser does not support passkeys.");
      }
      const optionsResponse = await fetch(passkeyForm.dataset.optionsUrl, {
        method: "POST",
        headers: { "X-CSRFToken": csrf, "Accept": "application/json" },
        credentials: "same-origin",
      });
      const options = await optionsResponse.json();
      if (!optionsResponse.ok) throw new Error(options.error || "Passkey enrollment could not start.");
      options.challenge = decodeBase64Url(options.challenge);
      options.user.id = decodeBase64Url(options.user.id);
      options.excludeCredentials = (options.excludeCredentials || []).map((item) => ({
        ...item,
        id: decodeBase64Url(item.id),
      }));
      const credential = await navigator.credentials.create({ publicKey: options });
      if (!credential) throw new Error("No passkey was created.");
      const completeResponse = await fetch(passkeyForm.dataset.completeUrl, {
        method: "POST",
        headers: { "X-CSRFToken": csrf, "Content-Type": "application/json", "Accept": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify({
          name: passkeyForm.elements.name.value,
          credential: registrationCredentialToJSON(credential),
        }),
      });
      const result = await completeResponse.json();
      if (!completeResponse.ok) throw new Error(result.error || "The passkey could not be registered.");
      window.location.reload();
    } catch (caught) {
      error.textContent = caught instanceof Error ? caught.message : "The passkey could not be registered.";
      error.hidden = false;
      button.disabled = false;
    }
  });
}
