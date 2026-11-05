export interface VsConfig {
  autoAnchor: {
    enabled: boolean;
    /** 마지막 앵커 이후 이만큼 커밋이 쌓이면 자동 앵커링. */
    everyNCommits: number;
    /** 마지막 앵커 이후 이만큼 시간(시)이 지나면 커밋 수와 무관하게 자동 앵커링. */
    maxAgeHours: number;
    tsaUrl: string;
    /** 커밋을 막지 않기 위한 타임아웃 — 네트워크가 느리거나 끊겨 있으면
     * 이 시간 안에 포기하고 다음 커밋에서 다시 시도한다. */
    timeoutMs: number;
  };
}

export const DEFAULT_CONFIG: VsConfig = {
  autoAnchor: {
    enabled: false,
    everyNCommits: 10,
    maxAgeHours: 24,
    tsaUrl: "https://freetsa.org/tsr",
    timeoutMs: 5000,
  },
};
