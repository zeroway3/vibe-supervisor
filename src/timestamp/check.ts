import type { LedgerEntry } from "../ledger/types.js";
import type { AnchorRecord } from "./store.js";
import { verifyTimestampToken, type TokenVerification } from "./rfc3161.js";

export interface AnchorCheck {
  anchor: AnchorRecord;
  /** 원장의 해당 레코드가 지금도 존재하는가 */
  entryExists: boolean;
  /** 토큰 검증 결과. data는 anchors.db에 적힌 해시가 아니라 **지금 원장의
   * 해당 레코드 해시**로 계산한다 — anchors.db를 같이 고쳐도 TSA 서명은
   * 다시 만들 수 없으므로 여기서 걸린다. */
  token: TokenVerification;
}

export async function checkAnchors(
  entries: LedgerEntry[],
  anchors: AnchorRecord[],
  trustedPem?: string
): Promise<AnchorCheck[]> {
  const results: AnchorCheck[] = [];
  for (const anchor of anchors) {
    const entry = entries.find((e) => e.id === anchor.ledgerEntryId);
    if (!entry) {
      results.push({
        anchor,
        entryExists: false,
        token: {
          ok: false,
          genTime: null,
          serialNumberHex: null,
          signer: null,
          chainChecked: false,
          message: `원장 #${anchor.ledgerEntryId}이(가) 없습니다.`,
        },
      });
      continue;
    }
    const token = await verifyTimestampToken(anchor.tokenDer, Buffer.from(entry.hash, "utf-8"), trustedPem);
    results.push({ anchor, entryExists: true, token });
  }
  return results;
}
