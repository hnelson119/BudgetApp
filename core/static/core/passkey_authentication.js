"use strict";

const passkeyAuthenticationForms = document.querySelectorAll("[data-passkey-authentication]");

function decodePasskeyValue(value) {
  const padding = "=".repeat((4 - (value.length % 4)) % 4);
  const binary = atob((value + padding).replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function encodePasskeyValue(value) {
  const bytes = new Uint8Array(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function authenticationCredentialToJSON(credential) {
  return {
    id: credential.id,
    rawId: encodePasskeyValue(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment,
    clientExtensionResults: credential.getClientExtensionResults(),
    response: {
      authenticatorData: encodePasskeyValue(credential.response.authenticatorData),
      clientDataJSON: encodePasskeyValue(credential.response.clientDataJSON),
      signature: encodePasskeyValue(credential.response.signature),
      userHandle: credential.response.userHandle
        ? encodePasskeyValue(credential.response.userHandle)
        : null,
    },
  };
}

for (const form of passkeyAuthenticationForms) {
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const error = form.querySelector("[data-passkey-authentication-error]");
    const button = form.querySelector("button[type='submit']");
    const csrf = form.querySelector("input[name='csrfmiddlewaretoken']").value;
    error.hidden = true;
    button.disabled = true;
    try {
      if (!window.PublicKeyCredential || !navigator.credentials) {
        throw new Error("This browser does not support passkeys.");
      }
      const optionsBody = new URLSearchParams(new FormData(form));
      const optionsResponse = await fetch(form.dataset.optionsUrl, {
        method: "POST",
        headers: {
          "X-CSRFToken": csrf,
          "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
          "Accept": "application/json",
        },
        credentials: "same-origin",
        body: optionsBody,
      });
      const options = await optionsResponse.json();
      if (!optionsResponse.ok) {
        throw new Error(options.error || "Passkey authentication could not start.");
      }
      options.challenge = decodePasskeyValue(options.challenge);
      if (options.allowCredentials) {
        options.allowCredentials = options.allowCredentials.map((item) => ({
          ...item,
          id: decodePasskeyValue(item.id),
        }));
      } else {
        delete options.allowCredentials;
      }
      const credential = await navigator.credentials.get({ publicKey: options });
      if (!credential) throw new Error("No passkey was selected.");
      const completeResponse = await fetch(form.dataset.completeUrl, {
        method: "POST",
        headers: {
          "X-CSRFToken": csrf,
          "Content-Type": "application/json",
          "Accept": "application/json",
        },
        credentials: "same-origin",
        body: JSON.stringify({ credential: authenticationCredentialToJSON(credential) }),
      });
      const result = await completeResponse.json();
      if (!completeResponse.ok) {
        throw new Error(result.error || "Passkey authentication was not accepted.");
      }
      window.location.assign(result.redirect);
    } catch (caught) {
      error.textContent = caught instanceof Error
        ? caught.message
        : "Passkey authentication was not accepted.";
      error.hidden = false;
      button.disabled = false;
    }
  });
}
