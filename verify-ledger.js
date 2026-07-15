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
const fs = require("fs");
const path = require("path");

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

/**
 * ตรวจ 1 บล็อก → {hashOk, sigOk}
 * sigOk: true=ลายเซ็นผ่าน · false=ไม่ผ่าน/ไม่มีลายเซ็นทั้งที่มี key/verify error
 *        · null=ไม่ได้ตรวจ (ไม่มี key = โหมด allow-unsigned)
 * [งาน B] ปิด downgrade เงียบ: มี key แต่บล็อกไม่เซ็น หรือ verify โยน exception
 * = false (ไม่ใช่ null ที่ผ่านฉลุยแบบ alg=none)
 */
function verifyOne(block, pubPem) {
  const canonical = canonicalize(canonicalBase(block));
  const hashOk = sha256hex(canonical) === block.blockHash;
  let sigOk = null;
  if (pubPem) {
    if (!block.serverSignature) {
      sigOk = false; // มี key แต่บล็อกไม่เซ็น = alg=none downgrade
    } else {
      try {
        sigOk = crypto.verify(
            null, Buffer.from(canonical, "utf8"),
            crypto.createPublicKey(pubPem),
            Buffer.from(block.serverSignature, "base64"));
      } catch (e) {
        sigOk = false; // verify error = ไม่ผ่าน (ไม่ข้ามเงียบ)
      }
    }
  }
  return {hashOk, sigOk};
}

// ---------------------------------------------------------------------------

/**
 * โหลด keys.json (trust-root) — pinned ในโฟลเดอร์เดียวกับ verifier
 * ไม่พึ่ง public key จาก endpoint (endpoint = เซิร์ฟเวอร์ที่เราควรตรวจ · ยึดได้)
 * @return {?object[]} รายการ key หรือ null ถ้าโหลด/parse ไม่ได้/ว่าง
 */
function loadTrustKeys() {
  try {
    const raw = fs.readFileSync(path.join(__dirname, "keys.json"), "utf8");
    const keys = JSON.parse(raw);
    return Array.isArray(keys) && keys.length > 0 ? keys : null;
  } catch (e) {
    return null;
  }
}

/**
 * หา key ที่ครอบ blockNumber ตามช่วง validFromBlock..validToBlock
 * @param {object[]} keys รายการจาก keys.json
 * @param {number} blockNumber เลขบล็อก
 * @return {?object} key entry (คืน {revoked:true} ถ้า status=revoked) หรือ null
 */
function keyForBlock(keys, blockNumber) {
  for (const k of keys) {
    const from = k.validFromBlock == null ? 0 : k.validFromBlock;
    const to = k.validToBlock == null ? Infinity : k.validToBlock;
    if (blockNumber >= from && blockNumber <= to) {
      if (k.status === "revoked") return {revoked: true, keyId: k.keyId};
      return k;
    }
  }
  return null;
}

/**
 * เลือก public key PEM สำหรับตรวจบล็อก + สัญญาณ forceFail
 * @param {?object[]} keys trust keys (null = โหมด allow-unsigned)
 * @param {number} blockNumber เลขบล็อก
 * @return {{pubPem: ?string, forceFail: boolean, reason: ?string}} ผล
 */
function resolveKeyForBlock(keys, blockNumber) {
  if (!keys) return {pubPem: null, forceFail: false, reason: null};
  const k = keyForBlock(keys, blockNumber);
  if (k === null) return {pubPem: null, forceFail: true, reason: "no-key-range"};
  if (k.revoked) return {pubPem: null, forceFail: true, reason: "revoked"};
  return {pubPem: k.publicKeyPem, forceFail: false, reason: null};
}

async function getJson(url) {
  const r = await fetch(url);
  if (!r.ok) throw new Error(`HTTP ${r.status} — ${url}`);
  return r.json();
}

async function main() {
  const rawArgs = process.argv.slice(2);
  const allowUnsigned = process.env.ALLOW_UNSIGNED === "1" ||
    rawArgs.includes("--allow-unsigned");
  const arg = rawArgs.filter((a) => !a.startsWith("--"))[0];
  const single = arg !== undefined ? Number(arg) : null;
  if (single !== null && (!Number.isInteger(single) || single < 0)) {
    throw new Error(`เลขบล็อกไม่ถูกต้อง: ${arg}`);
  }

  console.log("🔗 Independent Trust Ledger Verifier — Zone Analyst League");
  console.log(`   endpoint: ${BASE}\n`);

  const trustKeys = allowUnsigned ? null : loadTrustKeys();
  if (!allowUnsigned && !trustKeys) {
    console.error("❌ โหลด keys.json (trust-root) ไม่ได้ — ปฏิเสธ (fail-closed)");
    console.error("   keys.json ต้องอยู่ข้าง verify-ledger.js · ถ้าตั้งใจตรวจ");
    console.error("   แค่ hash chain (dev/debug) ใส่ flag --allow-unsigned");
    process.exit(2);
  }
  if (allowUnsigned) {
    console.log("⚠️  โหมด --allow-unsigned: ตรวจแค่ hash + เชน (ไม่ตรวจลายเซ็น)");
    console.log("    ผู้ควบคุม DB ปลอมได้ทั้งเส้น — ไม่ใช่การพิสูจน์เต็ม");
  } else {
    console.log(`🔑 trust-root: keys.json (${trustKeys.length} key · pinned)` +
      " — ตรวจลายเซ็นตามช่วงบล็อก");
  }

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
    const {pubPem, forceFail} = resolveKeyForBlock(trustKeys, block.blockNumber);
    const {hashOk, sigOk} = verifyOne(block, pubPem);
    const effSig = forceFail ? false : sigOk;
    let chainOk = true;
    if (single === null && n > 0) chainOk = block.previousBlockHash === prevHash;

    const ok = hashOk && effSig !== false && chainOk;
    if (ok) pass++; else fail++;

    const sigTxt = effSig === null ? "—" : (effSig ? "✅" : "❌");
    const chainTxt = (single !== null || n === 0) ? "—" : (chainOk ? "✅" : "❌");
    console.log(
        `#${String(n).padStart(3)} [${String(block.blockType).padEnd(10)}] ` +
        `hash ${hashOk ? "✅" : "❌"} · ลายเซ็น ${sigTxt} · เชน ${chainTxt}  ` +
        `${String(block.blockHash).slice(0, 16)}…`);
    prevHash = block.blockHash;
  }

  const mode = trustKeys ? "เชนสมบูรณ์ ไม่ถูกแก้" :
    "hash + เชน เท่านั้น (ยังไม่ตรวจลายเซ็น)";
  console.log(
      `\n${fail === 0 ? `✅ ผ่านทั้งหมด — ${mode}` : "❌ พบปัญหา!"} ` +
      `(ตรวจ ${pass + fail} บล็อก · ผ่าน ${pass} · ไม่ผ่าน ${fail})`);
  process.exit(fail === 0 ? 0 : 1);
}

module.exports = {
  verifyOne, canonicalize, canonicalBase, sha256hex,
  loadTrustKeys, keyForBlock, resolveKeyForBlock,
};

if (require.main === module) {
  main().catch((e) => {
    console.error("ERROR:", e.message);
    process.exit(2);
  });
}
