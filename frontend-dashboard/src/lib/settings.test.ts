import { describe, expect, it } from "vitest";

import { DEFAULT_SETTINGS, parseSettings, updateSettings } from "./settings";

describe("parseSettings", () => {
  it("revient aux valeurs par défaut sur un stockage absent ou corrompu", () => {
    expect(parseSettings(null)).toEqual(DEFAULT_SETTINGS);
    expect(parseSettings("{not json")).toEqual(DEFAULT_SETTINGS);
  });

  it("rejette les valeurs hors bornes champ par champ", () => {
    const parsed = parseSettings(JSON.stringify({ density: "huge", slaSeconds: -4, audioAlert: "yes", autoRefresh: false }));
    expect(parsed).toEqual({ ...DEFAULT_SETTINGS, autoRefresh: false });
  });

  it("persiste et applique la densité", () => {
    updateSettings({ density: "compact", slaSeconds: 45 });
    expect(parseSettings(localStorage.getItem("ra.ui-settings.v1"))).toMatchObject({ density: "compact", slaSeconds: 45 });
    expect(document.documentElement.style.getPropertyValue("--card-pad")).toBe("0.625rem");
  });
});
