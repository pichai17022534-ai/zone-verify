#!/usr/bin/env node
/**
 * Independent Trust Ledger Verifier — Zone Analyst League (ลีกนักวิเคราะห์โซน)
 * =========================================================================
 * เครื่องมือ "ตรวจสอบอิสระ" — ใครก็รันได้ ไม่ต้องเชื่อใจเซิร์ฟเวอร์เรา
 *
 * พิสูจน์ 3 อย่างต่อบล็อก โดยดึงเฉพาะข้อมูล "สาธารณะ" มาคำนวณซ้ำเอง:
 *   1) blockHash ถูกต้อง  — sha256(canonical JSON ของบล็อก) ตรงกับที่ประกาศ
 *   2) ลายเซ็นถูกต้อง     — Ed25519 verify ด้วย public key ของระบบ
 *   3) เชนต่อเนื่อง        — previousBlockHash ของบล็อก N = blockHash ของ N-1
 *
 * ถ้าผ่านครบ = ผลที่ประกาศไม่ถูกแก้ย้อนหลัง (แก้เมื่อไร hash เพี้ยน/ลายเซ็นพัง จับได้)
 * "ความลับ" เดียวคือ private key ที่เซิร์ฟเวอร์เก็บไว้เซ็น — verifier นี้ไม่ต้องใช้
 *
 * ใช้ Node.js ล้วน (built-in crypto + fetch) — ไม่มี dependency ภายนอกเลย
 *
 * วิธีใช้:
 *   node verify-ledger.js          # ตรวจทั้งเชน (block 0 → ล่าสุด)
 *   node verify-ledger.js 11       # ตรวจเฉพาะบล็อก #11 (hash + ลายเซ็น)
 *   LEDGER_BASE=<url> node verify-ledger.js   # ชี้ endpoint อื่น
 *
 * อัลกอริทึม canonical/hash/sign ตรงกับ functions_league/ledger.js เป๊ะ
 */
"use strict";

const crypto = require("crypto");

const BASE = process.env.LEDGER_BASE ||
  "https://us-central1-zonelottery23.cloudfunctions.net";

// ---------------------------------------------------------------------------
// pure crypto — สำเนาตรงจาก functions_league/ledger.js (ห้ามแก้ให้ต่าง)
// ---------------------------------------------------------------------------

/** canonical JSON: sort keys recursive, ไม่มี whitespace (deterministic) */
function canonicalize(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(canonicalize).join(",") + "]";
  const keys = Object.keys(value).sort();
  return "{" +
    keys.map((k) => JSON.stringify(k) + ":" + canonicalize(value[k])).join(",") +
    "}";
}

/** sha256 ของสตริง (utf8) → hex 64 ตัว */
function sha256hex(str) {
  return crypto.createHash("sha256").update(str, "utf8").digest("hex");
}

/** ฟิลด์ canonical ของบล็อก (ชุดเดียวกับ assembleBlock — ตัด blockHash/serverSignature) */
const CANON_FIELDS = [
  "blockNumber", "blockType", "seasonId", "drawId", "gameType",
  "winningNumber", "winningZone", "totalPredictions", "predictionMerkleRoot",
  "leaderboardRoot", "previousBlockHash", "correctsBlockNumber",
  "correctionReason", "createdAt",
];

/** หยิบเฉพาะฟิลด์ canonical (กันฟิลด์แปลกปลอมใน response มากวน hash) */
function canonicalBase(block) {
  const base = {};
  for (const k of CANON_FIELDS) {
    base[k] = block[k] === undefined ? null : block[k];
  }
  return base;
}

/** ตรวจ 1 บล็อก → {hashOk, sigOk} (sigOk=null ถ้าไม่มี key/ลายเซ็น) */
function verifyOne(block, pubPem) {
  const canonical = canonicalize(canonicalBase(block));
  const hashOk = sha256hex(canonical) === block.blockHash;
  let sigOk = null;
  if (pubPem && block.serverSignature) {
    sigOk = crypto.verify(
        null, Buffer.from(canonical, "utf8"),
        crypto.createPublicKey(pubPem),
        Buffer.from(block.serverSignature, "base64"));
  }
  return {hashOk, sigOk};
}

// ---------------------------------------------------------------------------

async function getJson(url) {
  const r = await fetch(url);
  if (!r.ok) throw new Error(`HTTP ${r.status} — ${url}`);
  return r.json();
}

async function main() {
  const arg = process.argv[2];
  const single = arg !== undefined ? Number(arg) : null;
  if (single !== null && (!Number.isInteger(single) || single < 0)) {
    throw new Error(`เลขบล็อกไม่ถูกต้อง: ${arg}`);
  }

  console.log("🔗 Independent Trust Ledger Verifier — Zone Analyst League");
  console.log(`   endpoint: ${BASE}\n`);

  const keyRes = await getJson(`${BASE}/ledgerPublic?key=1`);
  const pubPem = keyRes.publicKey || null;
  console.log(pubPem ?
    `🔑 public key: ${keyRes.algorithm} (โหลดแล้ว — จะตรวจลายเซ็น)` :
    "⚠️  ไม่มี public key — ข้ามการตรวจลายเซ็น");

  const head = await getJson(`${BASE}/ledgerPublic?head=1`);
  const latest = head.latestBlockNumber;
  console.log(`📦 หัวเชนล่าสุด: บล็อก #${latest}\n`);

  const from = single !== null ? single : 0;
  const to = single !== null ? single : latest;
  let prevHash = null;
  let pass = 0;
  let fail = 0;

  for (let n = from; n <= to; n++) {
    const block = await getJson(`${BASE}/ledgerPublic?block=${n}`);
    const {hashOk, sigOk} = verifyOne(block, pubPem);
    let chainOk = true;
    if (single === null && n > 0) chainOk = block.previousBlockHash === prevHash;

    const ok = hashOk && sigOk !== false && chainOk;
    if (ok) pass++; else fail++;

    const sigTxt = sigOk === null ? "—" : (sigOk ? "✅" : "❌");
    const chainTxt = (single !== null || n === 0) ? "—" : (chainOk ? "✅" : "❌");
    console.log(
        `#${String(n).padStart(3)} [${String(block.blockType).padEnd(10)}] ` +
        `hash ${hashOk ? "✅" : "❌"} · ลายเซ็น ${sigTxt} · เชน ${chainTxt}  ` +
        `${String(block.blockHash).slice(0, 16)}…`);
    prevHash = block.blockHash;
  }

  console.log(
      `\n${fail === 0 ? "✅ ผ่านทั้งหมด — เชนสมบูรณ์ ไม่ถูกแก้" : "❌ พบปัญหา!"} ` +
      `(ตรวจ ${pass + fail} บล็อก · ผ่าน ${pass} · ไม่ผ่าน ${fail})`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error("ERROR:", e.message);
  process.exit(2);
});
