import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { DEFAULT_CONFIG, VsConfig } from "./types.js";

export function loadConfig(configPath: string): VsConfig {
  if (!existsSync(configPath)) return structuredClone(DEFAULT_CONFIG);
  try {
    const raw = JSON.parse(readFileSync(configPath, "utf-8"));
    return { autoAnchor: { ...DEFAULT_CONFIG.autoAnchor, ...raw.autoAnchor } };
  } catch {
    // 설정 파일이 깨져 있어도 커밋 자체는 막으면 안 된다 — 기본값으로 안전하게 폴백.
    return structuredClone(DEFAULT_CONFIG);
  }
}

export function saveConfig(configPath: string, config: VsConfig) {
  const dir = dirname(configPath);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  writeFileSync(configPath, JSON.stringify(config, null, 2));
}
