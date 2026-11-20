# Security Specification — 나의 AI 프롬프트 창고

## 1. Data Invariants
1. Public guests (`request.auth == null`) have read-only (`get`, `list`) access to `/prompts/{promptId}`.
2. All writes (`create`, `update`, `delete`) on `/prompts/{promptId}` strictly require an authenticated admin whose `request.auth.token.email == 'ekgus899@gmail.com'` AND `request.auth.token.email_verified == true`.
3. Every document in `/prompts/{promptId}` must have a valid alphanumeric/hyphen/underscore `promptId` (`^[a-zA-Z0-9_\-]+$`, 1–128 chars).
4. Every `Prompt` document must contain strictly the 4 fields: `title`, `category`, `content`, `createdAt` (no shadow or unapproved fields).
5. `title` must be a non-empty string with length between 1 and 200 characters.
6. `category` must strictly belong to `['사진 합성', '스타일 변환', '캐릭터·포스터']`.
7. `content` must be a non-empty string with length between 1 and 20,000 characters.
8. `createdAt` must equal `request.time` on document creation and remain immutable (`incoming().createdAt == existing().createdAt`) on update.
9. All undeclared collections remain default-denied (`allow read, write: if false`).

## 2. The "Dirty Dozen" Payloads
1. **Unauthenticated Write (Guest Create/Update/Delete)**: Guest sends valid prompt payload -> Rejected (`isAdmin()` false).
2. **Non-Admin Authenticated User**: Signed-in user with `other@gmail.com` attempts create/update/delete -> Rejected (`email != 'ekgus899@gmail.com'`).
3. **Unverified Admin Email Spoof**: Signed-in user with `ekgus899@gmail.com` and `email_verified == false` -> Rejected (`email_verified == true` check).
4. **Shadow Field Injection (Admin)**: `{ title: "Test", category: "사진 합성", content: "Body", createdAt: serverTime, isAdmin: true }` -> Rejected (`hasOnly` check).
5. **Invalid Category Enum**: `{ title: "Test", category: "기타", content: "Body", createdAt: serverTime }` -> Rejected (`isValidCategory` check).
6. **Empty Title / Oversized Title (>200 chars)** -> Rejected (`title.size() >= 1 && title.size() <= 200`).
7. **Empty Content / Oversized Content (>20,000 chars)** -> Rejected (`content.size() >= 1 && content.size() <= 20000`).
8. **Wrong Field Type (Number instead of String)** -> Rejected (`is string`).
9. **Spoofed Past Timestamp on Create** -> Rejected (`createdAt == request.time`).
10. **Mutating `createdAt` on Update** -> Rejected (`affectedKeys().hasOnly(['title', 'category', 'content'])` and `incoming().createdAt == existing().createdAt`).
11. **ID Poisoning (>128 chars or invalid chars)** -> Rejected (`isValidId(promptId)`).
12. **Access to Unrelated Collection (`/admin/config`)** -> Rejected by global default-deny catch-all.
