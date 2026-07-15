# ⚓ External Anchors

โฟลเดอร์นี้เก็บ "หลักฐานตีตราเวลา" (external anchor) ของ Trust Ledger

แต่ละไฟล์ `anchor-YYYY-MM-DD-blockN.json` = สแนปช็อตหัวเชน ณ เวลาหนึ่ง
(`blockNumber` + `blockHash` ล่าสุด) commit ขึ้น GitHub ที่ตีตราเวลาให้อัตโนมัติ
→ พิสูจน์ว่า "เชนสถานะนี้มีอยู่จริงตั้งแต่วันที่ commit" (ย้อนแก้ไม่ได้ เพราะ
git history + timestamp ของ GitHub สาธารณะ)

- สร้างด้วย `anchor-head.js` (ดู `EXTERNAL_ANCHOR.md` ในโปรเจกต์)
- cadence: หลัง genesis (งวดแรก) + ตอนปิดแต่ละฤดูกาล

*(ยังว่าง — ไฟล์แรกจะมีหลัง genesis งวดแรก)*
