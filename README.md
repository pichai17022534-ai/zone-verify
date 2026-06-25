# 🔗 Trust Ledger — เครื่องมือตรวจสอบอิสระ (Independent Verifier)

เครื่องมือสำหรับ **ตรวจสอบความถูกต้องของ "สมุดบันทึกสาธารณะ" (Trust Ledger)** ของ Zone Analyst League
ด้วยตัวเอง — **ไม่ต้องเชื่อใจเซิร์ฟเวอร์ของเรา** ดึงเฉพาะข้อมูลสาธารณะมาคำนวณซ้ำเอง

## ทำอะไร
ทุกผลรางวัลที่ประกาศในลีกถูกบันทึกเป็น "บล็อก" ต่อกันเป็นเชน (hash-chain) + เซ็นด้วยลายเซ็นดิจิทัล
เครื่องมือนี้ตรวจ **3 อย่างต่อบล็อก**:

1. **blockHash ถูกต้อง** — คำนวณ `SHA-256` ของบล็อก (canonical JSON) ซ้ำ แล้วเทียบกับค่าที่ประกาศ
2. **ลายเซ็นถูกต้อง** — ตรวจ `Ed25519` ด้วย public key ของระบบ (ยืนยันว่าออกโดยเซิร์ฟเวอร์จริง)
3. **เชนต่อเนื่อง** — `previousBlockHash` ของบล็อก N ต้องเท่ากับ `blockHash` ของบล็อก N-1

ถ้าผ่านครบ = **ผลที่ประกาศไม่ถูกแก้ย้อนหลัง** (ถ้ามีใครแก้ แม้แต่ตัวอักษรเดียว → hash เพี้ยน / ลายเซ็นพัง → จับได้ทันที)

## ทำไมเชื่อถือได้
- **ความลับเดียว** ของระบบคือ *private key* ที่เซิร์ฟเวอร์เก็บไว้เซ็น — เครื่องมือนี้**ไม่ต้องใช้** (ใช้แค่ public key)
- เป็นหลักการเดียวกับลายเซ็นดิจิทัลของธนาคาร/บล็อกเชน: เปิดเผยวิธีตรวจได้หมด แต่ปลอมไม่ได้ถ้าไม่มีกุญแจลับ
- โค้ดนี้ **เปิดให้อ่าน/รันเองได้** ใช้ Node.js ล้วน (`crypto` + `fetch` ที่มากับ Node) **ไม่มี dependency ภายนอก**

## วิธีใช้
ต้องมี **Node.js 18 ขึ้นไป** (แนะนำ 20)
```bash
node verify-ledger.js          # ตรวจทั้งเชน (block 0 → ล่าสุด)
node verify-ledger.js 11       # ตรวจเฉพาะบล็อก #11 (hash + ลายเซ็น)
```
ชี้ endpoint อื่น (เช่น staging):
```bash
LEDGER_BASE=https://us-central1-zonelottery23.cloudfunctions.net node verify-ledger.js
```

ตัวอย่างผลลัพธ์:
```
🔑 public key: ed25519 (โหลดแล้ว — จะตรวจลายเซ็น)
📦 หัวเชนล่าสุด: บล็อก #11
#  0 [genesis ] hash ✅ · ลายเซ็น ✅ · เชน —  06c3f568db331d73…
#  1 [draw    ] hash ✅ · ลายเซ็น ✅ · เชน ✅  34a0e8fbfdf99585…
...
✅ ผ่านทั้งหมด — เชนสมบูรณ์ ไม่ถูกแก้ (ตรวจ 12 บล็อก · ผ่าน 12 · ไม่ผ่าน 0)
```

## ข้อมูลสาธารณะที่ใช้ (Public API)
| Endpoint | คืนอะไร |
|---|---|
| `GET /ledgerPublic?key=1` | public key (Ed25519) + ชื่ออัลกอริทึม |
| `GET /ledgerPublic?head=1` | เลขบล็อกล่าสุด + แฮชหัวเชน |
| `GET /ledgerPublic?block=N` | บล็อกที่ N (immutable) |

## สเปกอัลกอริทึม (ตรงกับ `functions_league/ledger.js`)
- **Canonical JSON:** เรียง key แบบ recursive · ไม่มี whitespace · timestamp เป็น ISO UTC
- **blockHash** = `sha256hex(canonicalize(บล็อกที่ตัด blockHash + serverSignature ออก))`
- **serverSignature** = `Ed25519.sign(canonical เดียวกัน)` เข้ารหัส base64
- ฟิลด์ canonical 14 ตัว: blockNumber, blockType, seasonId, drawId, gameType, winningNumber,
  winningZone, totalPredictions, predictionMerkleRoot, leaderboardRoot, previousBlockHash,
  correctsBlockNumber, correctionReason, createdAt

---
*Zone Analyst League · Trust Ledger Phase 6 (Independent Verifier) · ไร้เงินเดิมพัน — ความน่าเชื่อถือคือคุณค่า*
