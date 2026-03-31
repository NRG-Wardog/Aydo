import type { AntivirusEngine } from "./engine";
import { AntivirusSimulator } from "./simulator";
import { ClientEngine } from "./clientEngine";

export const createAntivirusEngine = (): AntivirusEngine => {
  const mode = (process.env.AYDO_ENGINE ?? "client").toLowerCase();

  if (mode === "simulator") {
    return new AntivirusSimulator();
  }

  const client = new ClientEngine();
  if (mode === "client") {
    return client;
  }

  if (client.isAvailable()) {
    return client;
  }

  return new AntivirusSimulator();
};
