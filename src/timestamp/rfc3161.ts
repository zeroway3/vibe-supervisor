// RFC3161 신뢰 타임스탬프 클라이언트. 감독 원장의 "소급생성 방지" 구멍(Q4-2
// 멘토 요청 1번 — 해시체인은 변조는 막지만, 감사 직전에 전체를 새로 만들면
// 체인은 일관되게 생성된다)을 메우는 용도. 외부 독립 기관(TSA)이 "이 해시가
// 이 시각에 존재했다"는 걸 자기 서명으로 증명해주므로, 나중에 전체를 다시
// 만들면 과거 앵커 시점의 해시와 지금 해시가 달라져서 검출된다.
import * as pkijs from "pkijs";
import * as asn1js from "asn1js";
import { webcrypto, randomBytes } from "node:crypto";

pkijs.setEngine("node", new pkijs.CryptoEngine({ name: "node", crypto: webcrypto as unknown as Crypto }));

export interface TimestampResult {
  tokenDer: Buffer;
  genTime: string;
  serialNumberHex: string;
}

/** FreeTSA는 데모/검증용. 실제 운영에서는 정책에 맞는 상용/공인 TSA를 선택해야
 * 한다 — Q4-1 사업화 계획의 "오픈소스 라이선스 법률 검토"와 같은 층위의,
 * 가볍게 넘길 결정이 아니다. */
export const KNOWN_TSA_URLS = {
  freetsa: "https://freetsa.org/tsr",
};

export async function requestTimestamp(
  hash: Buffer,
  tsaUrl: string = KNOWN_TSA_URLS.freetsa
): Promise<TimestampResult> {
  const hashBytes = new Uint8Array(hash); // Buffer의 ArrayBufferLike(SharedArrayBuffer 포함 가능)를
  // pkijs가 기대하는 순수 ArrayBuffer 기반 BufferSource로 명확히 좁힌다.
  const messageImprint = await pkijs.MessageImprint.create("SHA-256", hashBytes);
  const nonceBytes = randomBytes(8);

  const req = new pkijs.TimeStampReq({
    version: 1,
    messageImprint,
    certReq: true,
    nonce: new asn1js.Integer({ valueHex: nonceBytes.buffer as ArrayBuffer }),
  });

  const reqDer = Buffer.from(req.toSchema().toBER(false));

  const res = await fetch(tsaUrl, {
    method: "POST",
    headers: { "Content-Type": "application/timestamp-query" },
    body: new Uint8Array(reqDer),
  });
  if (!res.ok) {
    throw new Error(`TSA 요청 실패: HTTP ${res.status}`);
  }
  const respBuf = Buffer.from(await res.arrayBuffer());

  const asn1 = asn1js.fromBER(respBuf);
  if (asn1.offset === -1) throw new Error("TSA 응답을 ASN.1로 파싱할 수 없습니다.");
  const resp = new pkijs.TimeStampResp({ schema: asn1.result });

  if (resp.status.status !== 0 && resp.status.status !== 1) {
    // 0=granted, 1=grantedWithMods. 그 외는 거부/오류.
    throw new Error(`TSA가 타임스탬프 발급을 거부했습니다 (status=${resp.status.status}).`);
  }
  if (!resp.timeStampToken) {
    throw new Error("TSA 응답에 timeStampToken이 없습니다.");
  }

  const cms = new pkijs.ContentInfo({ schema: resp.timeStampToken.toSchema() });
  const signedData = new pkijs.SignedData({ schema: cms.content });
  const eContent = signedData.encapContentInfo.eContent;
  if (!eContent) throw new Error("TSA 응답의 SignedData에 eContent가 없습니다.");
  const tstInfoAsn1 = asn1js.fromBER(eContent.valueBlock.valueHexView.slice().buffer);
  const tstInfo = new pkijs.TSTInfo({ schema: tstInfoAsn1.result });

  return {
    tokenDer: Buffer.from(resp.timeStampToken.toSchema().toBER(false)),
    genTime: tstInfo.genTime.toISOString(),
    serialNumberHex: Buffer.from(tstInfo.serialNumber.valueBlock.valueHexView).toString("hex"),
  };
}
