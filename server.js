// ============================================================
//  AutoDM — Instagram Comment-to-DM Bot
//  Uses: Instagram API with Instagram Login (2024+ API)
//  No Facebook Page required.
// ============================================================
//
//  REQUIRED ENV VARS (set these in Railway/Render/etc):
//
//    IG_APP_SECRET      — from Meta App Dashboard > App Settings > Basic > App Secret
//    VERIFY_TOKEN       — a secret string YOU make up (e.g. "mySecretVerify123")
//    ACCESS_TOKEN       — your long-lived Instagram User access token (see SETUP.md)
//    PORT               — optional, defaults to 3000
//
// ============================================================

const express = require('express');
const crypto  = require('crypto'); // built into Node — no install needed
const axios   = require('axios');

const app = express();

// ── Parse raw body BEFORE json() so we can verify the signature ──────────────
// Meta signs every webhook POST with your App Secret.
// We need the raw bytes to verify that signature.
app.use(express.json({
  verify: (req, _res, buf) => { req.rawBody = buf; }
}));

// ── Config ────────────────────────────────────────────────────────────────────
const APP_SECRET   = process.env.IG_APP_SECRET;
const VERIFY_TOKEN = process.env.VERIFY_TOKEN;
const ACCESS_TOKEN = process.env.ACCESS_TOKEN;
const PAGE_ID = process.env.PAGE_ID;
const PORT         = process.env.PORT || 3000;

if (!APP_SECRET || !VERIFY_TOKEN || !ACCESS_TOKEN) {
  console.error('ERROR: Missing required environment variables.');
  console.error('Need: IG_APP_SECRET, VERIFY_TOKEN, ACCESS_TOKEN');
  process.exit(1);
}

// ── Your keyword → DM rules ───────────────────────────────────────────────────
// Edit these to set your triggers and messages.
// Use {name} anywhere in the message to insert the commenter's first name.
// Rules are checked top to bottom — first match wins.
const RULES = [
  {
    keyword: 'LINK',
    message: 'Hey {name}! 👋 Here\'s the link you asked for: https://youtube.com',
    active: true
  },
  {
    keyword: 'PRICE',
    message: 'Hi {name}! Our pricing starts from $XX — DM me for the full breakdown 💬',
    active: true
  },
  {
    keyword: 'INFO',
    message: 'Hey {name}! Thanks for your interest. Here\'s everything you need to know: [your info]',
    active: true
  },
];

// ── Per-user DM cooldown (prevent spamming the same person) ──────────────────
// Stores { userId: timestamp } of last DM sent.
// Won't DM the same person again within COOLDOWN_MS milliseconds.
const lastDMSent   = new Map();
const COOLDOWN_MS  = 24 * 60 * 60 * 1000; // 24 hours

function isOnCooldown(userId) {
  const last = lastDMSent.get(userId);
  if (!last) return false;
  return (Date.now() - last) < COOLDOWN_MS;
}

function setCooldown(userId) {
  lastDMSent.set(userId, Date.now());
}

// ── Security: verify Meta's webhook signature ──────────────────────────────── 
// Meta signs every POST with HMAC-SHA256 using your App Secret.
// If the signature doesn't match, the request is fake — reject it.
function verifySignature(req, res, next) {
  const signature = req.headers['x-hub-signature-256'];

  if (!signature) {
    console.warn('[Security] Missing x-hub-signature-256 header — rejected.');
    return res.sendStatus(401);
  }

  const expected = 'sha256=' + crypto
    .createHmac('sha256', APP_SECRET)
    .update(req.rawBody)
    .digest('hex');

  const sigBuffer      = Buffer.from(signature, 'utf8');
  const expectedBuffer = Buffer.from(expected, 'utf8');

  // Use timingSafeEqual to prevent timing attacks
  if (sigBuffer.length !== expectedBuffer.length ||
      !crypto.timingSafeEqual(sigBuffer, expectedBuffer)) {
    console.warn('[Security] Signature mismatch — request rejected.');
    return res.sendStatus(401);
  }

  next();
}

// ── GET /webhook — Meta verifies your endpoint ────────────────────────────────
// When you paste your URL into Meta's dashboard, Meta sends this GET request.
// You must respond with hub.challenge to prove you control the server.
app.get('/webhook', (req, res) => {
  const mode      = req.query['hub.mode'];
  const token     = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];

  if (mode === 'subscribe' && token === VERIFY_TOKEN) {
    console.log('[Webhook] Endpoint verified by Meta.');
    return res.status(200).send(challenge);
  }

  console.warn('[Webhook] Verification failed — token mismatch.');
  res.sendStatus(403);
});

// ── POST /webhook — receive comment events ────────────────────────────────────
app.post('/webhook', verifySignature, async (req, res) => {
  // Always respond 200 immediately.
  // Meta will retry failed deliveries — a slow response causes duplicate events.
  res.sendStatus(200);

  const body = req.body;
  if (body.object !== 'instagram') return;

  for (const entry of (body.entry || [])) {
    for (const change of (entry.changes || [])) {

      // Only handle comment events (not messages, reactions, etc.)
      if (change.field !== 'comments') continue;

      const { from, text, comment_id } = change.value || {};
      if (!from || !text) continue;

      const userId    = from.id;
      const username  = from.username || 'unknown';
      const firstName = username.split('_')[0] || 'there'; // rough first-name guess from username
      const lowerText = text.toLowerCase().trim();

      console.log(`[Comment] @${username}: "${text}"`);

      // Skip if this user was already DM'd recently
      if (isOnCooldown(userId)) {
        console.log(`[Cooldown] Skipping @${username} — DM'd recently.`);
        continue;
      }

      // Find the first matching active rule
      let matched = false;
      for (const rule of RULES) {
        if (!rule.active) continue;
        if (lowerText.includes(rule.keyword.toLowerCase())) {
          const message = rule.message.replace(/{name}/gi, firstName);
          try {
            await sendDM(comment_id, message);
            setCooldown(userId);
            console.log(`[DM Sent] → @${username} matched keyword "${rule.keyword}"`);
            matched = true;
          } catch (err) {
            console.error('comment_id')
            console.error(`[DM Failed] → @${username}:`, err.response?.data || err.message);
          }
          break; // Only one DM per comment
        }
      }

      if (!matched) {
        console.log(`[No Match] No rule matched for: "${text}"`);
      }
    }
  }
});

// ── Send a Private Reply via Instagram Graph API ──────────────────────────────
// Uses the comment_id (not user_id) as the recipient.
// Requires: instagram_business_manage_comments permission only.
async function sendDM(commentId, messageText) {
  console.log('Webhook change.value:', JSON.stringify(change.value));
  console.log('Sending private reply to comment_id:', commentId);
  console.log('Message:', messageText);
  const url = `https://graph.instagram.com/v21.0/${PAGE_ID}/messages`; 
  const response = await axios.post(
    url,
    {
      recipient:   { comment_id: commentId },  // <-- key change: comment_id not user id
      message: { text : messageText }
      // no messaging_type needed for private replies
    },
    {
      headers: { Authorization: `Bearer ${ACCESS_TOKEN}` },
      'Content-Type': 'application/json'
    }
  );
  return response.data;
}

// ── Health check ──────────────────────────────────────────────────────────────
app.get('/', (_req, res) => {
  const activeRules = RULES.filter(r => r.active).map(r => r.keyword);
  res.json({
    status:       'AutoDM running',
    activeRules,
    cooldownHours: COOLDOWN_MS / 3600000
  });
});

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`AutoDM server running on port ${PORT}`);
  console.log(`Active rules TESTTINGGGGGGGGGGGG: ${RULES.filter(r => r.active).map(r => r.keyword).join(', ')}`);
});
