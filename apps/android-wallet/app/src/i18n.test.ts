import { expect, test } from "vitest";

import { localizedNativeMessage, resolveLanguage } from "./i18n";

test("automatic language supports regional English and French variants", () => {
  expect(resolveLanguage("automatic", "fr-CA")).toBe("fr");
  expect(resolveLanguage("automatic", "fr-FR")).toBe("fr");
  expect(resolveLanguage("automatic", "en-CA")).toBe("en");
  expect(resolveLanguage("automatic", "en-US")).toBe("en");
});

test("automatic language falls back to English and manual choices win", () => {
  expect(resolveLanguage("automatic", "es-MX")).toBe("en");
  expect(resolveLanguage("en", "fr-CA")).toBe("en");
  expect(resolveLanguage("fr", "en-CA")).toBe("fr");
});

test("native messages use stable localized presentation without exposing unknown English details", () => {
  expect(
    localizedNativeMessage(
      "Les fonds réellement dépensables sont insuffisants, frais compris.",
      "en",
      "Safe failure",
    ),
  ).toBe("Spendable funds are insufficient, including fees.");
  expect(
    localizedNativeMessage(
      "L’envoi mainnet est désactivé dans les versions de développement débogables. Utilisez une version release signée et validée.",
      "en",
      "Safe failure",
    ),
  ).toBe(
    "Mainnet sending is disabled in debuggable development builds. Use a signed and validated release build.",
  );
  expect(localizedNativeMessage("/private/path", "en", "Safe failure")).toBe("Safe failure");
  expect(localizedNativeMessage("Message sûr", "fr", "Échec sûr")).toBe("Message sûr");
});
