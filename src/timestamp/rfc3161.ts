// RFC3161 신뢰 타임스탬프 클라이언트. 감독 원장의 "소급생성 방지" 구멍(Q4-2
// 멘토 요청 1번 — 해시체인은 변조는 막지만, 감사 직전에 전체를 새로 만들면
// 체인은 일관되게 생성된다)을 메우는 용도. 외부 독립 기관(TSA)이 "이 해시가
// 이 시각에 존재했다"는 걸 자기 서명으로 증명해주므로, 나중에 전체를 다시
// 만들면 과거 앵커 시점의 해시와 지금 해시가 달라져서 검출된다.
import * as pkijs from "pkijs";
import * as asn1js from "asn1js";
import { webcrypto, randomBytes, X509Certificate } from "node:crypto";

pkijs.setEngine("node", new pkijs.CryptoEngine({ name: "node", crypto: webcrypto as unknown as Crypto }));

export interface TimestampResult {
  tokenDer: Buffer;
  genTime: string;
  serialNumberHex: string;
}

export interface TokenVerification {
  /** 서명·imprint·(요청 시)신뢰 체인까지 전부 통과했는가 */
  ok: boolean;
  /** 토큰 안의 TSA 서명 시각 — DB에 따로 저장된 값이 아니라 서명된 값이다. */
  genTime: string | null;
  serialNumberHex: string | null;
  /** 서명자 인증서의 주체(subject) */
  signer: string | null;
  /** 신뢰 루트를 지정해 체인까지 확인했는지. false면 "서명은 유효하나
   * 그 서명자가 믿을 만한 TSA인지는 확인 안 함" 상태다. */
  chainChecked: boolean;
  message: string;
}

/** FreeTSA는 데모/검증용. 실제 운영에서는 정책에 맞는 상용/공인 TSA를 선택해야
 * 한다 — Q4-1 사업화 계획의 "오픈소스 라이선스 법률 검토"와 같은 층위의,
 * 가볍게 넘길 결정이 아니다. */
export const KNOWN_TSA_URLS = {
  freetsa: "https://freetsa.org/tsr",
};

function toArrayBuffer(buf: Buffer | Uint8Array): ArrayBuffer {
  // Buffer의 ArrayBufferLike(SharedArrayBuffer 포함 가능)를 pkijs가 기대하는
  // 순수 ArrayBuffer로 복사해서 넘긴다.
  return new Uint8Array(buf).buffer as ArrayBuffer;
}

function parseSignedData(tokenDer: Buffer): pkijs.SignedData {
  const asn1 = asn1js.fromBER(toArrayBuffer(tokenDer));
  if (asn1.offset === -1) throw new Error("타임스탬프 토큰을 ASN.1로 파싱할 수 없습니다.");
  const cms = new pkijs.ContentInfo({ schema: asn1.result });
  return new pkijs.SignedData({ schema: cms.content });
}

function readTstInfo(signedData: pkijs.SignedData): pkijs.TSTInfo {
  const eContent = signedData.encapContentInfo.eContent;
  if (!eContent) throw new Error("타임스탬프 토큰의 SignedData에 eContent가 없습니다.");
  return pkijs.TSTInfo.fromBER(eContent.valueBlock.valueHexView.slice().buffer);
}

function pemToCertificates(pem: string): pkijs.Certificate[] {
  const blocks = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) ?? [];
  return blocks.map((b) => pkijs.Certificate.fromBER(toArrayBuffer(new X509Certificate(b).raw)));
}

/**
 * 저장된 토큰이 정말로 `data`에 대해 TSA가 서명한 것인지 오프라인으로 검증한다.
 *
 * 1. CMS 서명이 토큰에 동봉된 서명자 인증서로 검증되는가 (토큰 위조·변조 검출)
 * 2. 서명된 TSTInfo의 messageImprint가 sha256(data)와 같은가 (다른 해시용 토큰을
 *    가져다 붙인 것 검출)
 * 3. trustedPem을 주면 서명자 인증서가 그 루트로 이어지는가 (아무나 만든 자체
 *    서명 TSA 검출)
 *
 * 3번 없이는 공격자가 직접 만든 가짜 TSA로 "서명은 유효한" 토큰을 만들 수 있다.
 * 그래서 chainChecked를 결과에 그대로 드러내고, 리포트에도 표기한다.
 */
export async function verifyTimestampToken(
  tokenDer: Buffer,
  data: Buffer,
  trustedPem?: string
): Promise<TokenVerification> {
  let signedData: pkijs.SignedData;
  let tstInfo: pkijs.TSTInfo;
  try {
    signedData = parseSignedData(tokenDer);
    tstInfo = readTstInfo(signedData);
  } catch (err: any) {
    return { ok: false, genTime: null, serialNumberHex: null, signer: null, chainChecked: false, message: err.message };
  }

  const genTime = tstInfo.genTime.toISOString();
  const serialNumberHex = Buffer.from(tstInfo.serialNumber.valueBlock.valueHexView).toString("hex");
  const trustedCerts = trustedPem ? pemToCertificates(trustedPem) : [];
  const chainChecked = trustedCerts.length > 0;

  try {
    // data를 넘기면 pkijs가 TSTInfo의 messageImprint와 sha(data)를 비교하고,
    // 이어서 서명자 인증서로 CMS 서명을 검증한다. checkDate는 내부에서
    // genTime으로 바뀌므로 "서명 당시 유효했던 인증서인가"로 판단된다.
    const result = await signedData.verify({
      signer: 0,
      data: toArrayBuffer(data),
      trustedCerts,
      checkChain: chainChecked,
      extendedMode: true,
    });
    // 리포트에 찍을 서명자 이름은 CN(없으면 O)만 쓴다.
    const subject = result.signerCertificate?.subject.typesAndValues ?? [];
    const signer =
      (subject.find((tv) => tv.type === "2.5.4.3") ?? subject.find((tv) => tv.type === "2.5.4.10"))?.value.valueBlock
        .value ?? null;
    if (!result.signatureVerified) {
      return { ok: false, genTime, serialNumberHex, signer, chainChecked, message: `서명 검증 실패: ${result.message}` };
    }
    if (chainChecked && !result.signerCertificateVerified) {
      return { ok: false, genTime, serialNumberHex, signer, chainChecked, message: "서명자 인증서가 지정한 신뢰 루트로 이어지지 않습니다." };
    }
    return { ok: true, genTime, serialNumberHex, signer, chainChecked, message: "OK" };
  } catch (err: any) {
    // SignedDataVerifyError — imprint 불일치도 여기로 온다.
    const msg: string = err.message ?? String(err);
    return {
      ok: false,
      genTime,
      serialNumberHex,
      signer: null,
      chainChecked,
      message: /TSTInfo verification/i.test(msg) ? `TSA가 ${genTime}에 서명한 해시와 지금 원장의 해시가 다릅니다.` : msg,
    };
  }
}

export async function requestTimestamp(
  data: Buffer,
  tsaUrl: string = KNOWN_TSA_URLS.freetsa,
  signal?: AbortSignal
): Promise<TimestampResult> {
  const messageImprint = await pkijs.MessageImprint.create("SHA-256", new Uint8Array(data));
  const nonceBytes = randomBytes(8);
  // DER INTEGER는 부호가 있어서 최상위 비트가 1이면 음수로 읽힌다 — 응답 nonce와
  // 바이트 단위로 비교하려면 양수로 고정해야 한다.
  nonceBytes[0] &= 0x7f;

  const req = new pkijs.TimeStampReq({
    version: 1,
    messageImprint,
    certReq: true,
    nonce: new asn1js.Integer({ valueHex: toArrayBuffer(nonceBytes) }),
  });

  const reqDer = Buffer.from(req.toSchema().toBER(false));

  const res = await fetch(tsaUrl, {
    method: "POST",
    headers: { "Content-Type": "application/timestamp-query" },
    body: new Uint8Array(reqDer),
    signal,
  });
  if (!res.ok) {
    throw new Error(`TSA 요청 실패: HTTP ${res.status}`);
  }
  const respBuf = Buffer.from(await res.arrayBuffer());

  const asn1 = asn1js.fromBER(toArrayBuffer(respBuf));
  if (asn1.offset === -1) throw new Error("TSA 응답을 ASN.1로 파싱할 수 없습니다.");
  const resp = new pkijs.TimeStampResp({ schema: asn1.result });

  if (resp.status.status !== 0 && resp.status.status !== 1) {
    // 0=granted, 1=grantedWithMods. 그 외는 거부/오류.
    throw new Error(`TSA가 타임스탬프 발급을 거부했습니다 (status=${resp.status.status}).`);
  }
  if (!resp.timeStampToken) {
    throw new Error("TSA 응답에 timeStampToken이 없습니다.");
  }

  const tokenDer = Buffer.from(resp.timeStampToken.toSchema().toBER(false));
  const tstInfo = readTstInfo(parseSignedData(tokenDer));

  // 재전송(replay) 방지: 우리가 보낸 nonce가 그대로 돌아왔는지 확인한다.
  const respNonce = tstInfo.nonce ? Buffer.from(tstInfo.nonce.valueBlock.valueHexView) : null;
  if (!respNonce || Buffer.compare(stripLeadingZeros(respNonce), stripLeadingZeros(nonceBytes)) !== 0) {
    throw new Error("TSA 응답의 nonce가 요청과 다릅니다 — 재전송된 응답일 수 있어 저장하지 않습니다.");
  }

  // 받은 즉시 서명과 imprint를 검증한다. 검증 안 된 토큰은 저장하지 않는다.
  const check = await verifyTimestampToken(tokenDer, data);
  if (!check.ok) {
    throw new Error(`TSA 응답 검증 실패 — ${check.message}`);
  }

  return {
    tokenDer,
    genTime: tstInfo.genTime.toISOString(),
    serialNumberHex: Buffer.from(tstInfo.serialNumber.valueBlock.valueHexView).toString("hex"),
  };
}

function stripLeadingZeros(b: Buffer): Buffer {
  let i = 0;
  while (i < b.length - 1 && b[i] === 0) i++;
  return b.subarray(i);
}
