export type OriginConfidence = "confirmed" | "estimated" | "unknown";

export type LedgerEventType = "generated" | "detected" | "fixed" | "approved";

export interface FileHash {
  path: string;
  /** sha256 of the file's full content at this commit. MVP uses whole-file
   * hashing; byte-range hashing per AI-generated hunk is a later refinement
   * once origin tracking moves past the commit-trailer method. */
  hash: string;
}

export interface LedgerEntryInput {
  eventType: LedgerEventType;
  commitHash: string;
  actor: string;
  aiTool: string | null;
  originConfidence: OriginConfidence;
  fileHashes: FileHash[];
}

export interface LedgerEntry extends LedgerEntryInput {
  id: number;
  timestamp: string;
  prevHash: string | null;
  hash: string;
}
