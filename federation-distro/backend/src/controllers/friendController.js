const { config } = require("../config/env");
const friendService = require("../services/friendService");
const { broadcastToUser, getEnrichedConversations } = require("../services/websocketServer");

function getSessionToken(req) {
  return req.signedCookies?.[config.cookieNames.session] || req.cookies?.[config.cookieNames.session];
}

const sessionRepository = require("../repositories/sessionRepository");
const { hashSessionToken } = require("../security/sessionToken");

async function requireAuth(req) {
  const token = getSessionToken(req);
  if (!token) return null;
  return sessionRepository.findUserBySession(hashSessionToken(token));
}

async function pushFriendAcceptedConversations(result) {
  if (!result?.requesterId || !result?.addresseeId) return;

  const [requesterConversations, addresseeConversations] = await Promise.all([
    getEnrichedConversations(result.requesterId),
    getEnrichedConversations(result.addresseeId),
  ]);

  broadcastToUser(result.requesterId, { type: "conversations", conversations: requesterConversations });
  broadcastToUser(result.addresseeId, { type: "conversations", conversations: addresseeConversations });
  broadcastToUser(result.requesterId, {
    type: "friend_accepted",
    partnerId: result.addresseePublicId,
    conversations: requesterConversations,
  });
  // Refresh both sides' friend + pending lists live (the new friend appears, the
  // pending request clears).
  broadcastToUser(result.requesterId, { type: "friends_changed" });
  broadcastToUser(result.addresseeId, { type: "friends_changed" });
}

async function getFriends(req, res, next) {
  try {
    const user = await requireAuth(req);
    if (!user) return res.status(401).json({ message: "Not signed in." });

    const friends = await friendService.getFriends(user.user_id);
    return res.json({ friends });
  } catch (err) {
    return next(err);
  }
}

async function getPending(req, res, next) {
  try {
    const user = await requireAuth(req);
    if (!user) return res.status(401).json({ message: "Not signed in." });

    const received = await friendService.getPendingIncoming(user.user_id);
    const sent = await friendService.getPendingOutgoing(user.user_id);
    return res.json({ pending: received, received, sent });
  } catch (err) {
    return next(err);
  }
}

async function getBlocked(req, res, next) {
  try {
    const user = await requireAuth(req);
    if (!user) return res.status(401).json({ message: "Not signed in." });

    const search = typeof req.query.search === "string" ? req.query.search : "";
    const blocked = await friendService.getBlockedUsers(user.user_id, search);
    return res.json({ blocked });
  } catch (err) {
    return next(err);
  }
}

async function getBlockState(req, res, next) {
  try {
    const user = await requireAuth(req);
    if (!user) return res.status(401).json({ message: "Not signed in." });

    const result = await friendService.getBlockState({
      userId: user.user_id,
      targetUserId: req.params.userId,
    });
    return res.json(result);
  } catch (err) {
    return next(err);
  }
}

// Friend-request send caps (in-memory, rolling 1-hour window). Two independent
// limits, both counting only SUCCESSFUL new requests so failed lookups / dupes
// don't burn the budget: 5 per hour per account, 10 per hour per IP. trust proxy
// is set, so req.ip is the real client address.
const FRIEND_REQ_WINDOW_MS = 60 * 60 * 1000;
const FRIEND_REQ_LIMITS = { account: 5, ip: 10 };
const friendReqBuckets = { account: new Map(), ip: new Map() };

// Live (within-window) timestamps for one key, trimmed in place. The returned
// array is the same reference stored in the map, so callers can push to record.
function friendReqHits(kind, key) {
  const now = Date.now();
  const map = friendReqBuckets[kind];
  const live = (map.get(key) || []).filter((t) => now - t < FRIEND_REQ_WINDOW_MS);
  map.set(key, live);
  return live;
}

// Which cap (if any) is already maxed for this account/IP - checked BEFORE sending.
function friendReqLimitHit(userId, ip) {
  if (friendReqHits("account", userId).length >= FRIEND_REQ_LIMITS.account) return "account";
  if (friendReqHits("ip", ip).length >= FRIEND_REQ_LIMITS.ip) return "ip";
  return null;
}

function recordFriendReq(userId, ip) {
  const now = Date.now();
  friendReqHits("account", userId).push(now);
  friendReqHits("ip", ip).push(now);
}

async function sendRequest(req, res, next) {
  try {
    const user = await requireAuth(req);
    if (!user) return res.status(401).json({ message: "Not signed in." });

    const { username } = req.body;
    if (!username || typeof username !== "string" || username.trim().length < 3) {
      return res.status(400).json({ message: "Enter a valid username." });
    }

    const ip = req.ip || "unknown";
    const limited = friendReqLimitHit(user.user_id, ip);
    if (limited === "account") {
      return res.status(429).json({ message: "You can only send 5 friend requests per hour. Try again later." });
    }
    if (limited === "ip") {
      return res.status(429).json({ message: "Too many friend requests from your network. Try again later." });
    }

    const result = await friendService.sendFriendRequest({
      requesterId: user.user_id,
      targetUsername: username.trim(),
    });

    if (result.action === "accepted") {
      await pushFriendAcceptedConversations(result);
    } else if (result.action === "requested" && result.addresseeId) {
      // Push to the recipient so the incoming request shows up immediately
      // instead of waiting for their 30s poll.
      broadcastToUser(result.addresseeId, { type: "friends_changed" });
    }

    // Only a genuinely-sent new request counts toward the hourly caps.
    if (result.action === "requested") recordFriendReq(user.user_id, ip);

    return res.json(result);
  } catch (err) {
    return next(err);
  }
}

async function acceptRequest(req, res, next) {
  try {
    const user = await requireAuth(req);
    if (!user) return res.status(401).json({ message: "Not signed in." });

    const result = await friendService.acceptRequest({
      friendshipId: req.params.id,
      userId: user.user_id,
    });

    await pushFriendAcceptedConversations(result);

    return res.json({ ok: true, friend: result.friend });
  } catch (err) {
    return next(err);
  }
}

async function declineRequest(req, res, next) {
  try {
    const user = await requireAuth(req);
    if (!user) return res.status(401).json({ message: "Not signed in." });

    const { otherId } = await friendService.declineRequest({
      friendshipId: req.params.id,
      userId: user.user_id,
    });
    if (otherId) broadcastToUser(otherId, { type: "friends_changed" });
    return res.json({ ok: true });
  } catch (err) {
    return next(err);
  }
}

async function cancelRequest(req, res, next) {
  try {
    const user = await requireAuth(req);
    if (!user) return res.status(401).json({ message: "Not signed in." });

    const { otherId } = await friendService.cancelRequest({
      friendshipId: req.params.id,
      userId: user.user_id,
    });
    if (otherId) broadcastToUser(otherId, { type: "friends_changed" });
    return res.json({ ok: true });
  } catch (err) {
    return next(err);
  }
}

async function removeFriend(req, res, next) {
  try {
    const user = await requireAuth(req);
    if (!user) return res.status(401).json({ message: "Not signed in." });

    await friendService.removeFriend({
      friendshipId: req.params.id,
      userId: user.user_id,
    });
    return res.status(204).send();
  } catch (err) {
    return next(err);
  }
}

async function purgeFriends(req, res, next) {
  try {
    const user = await requireAuth(req);
    if (!user) return res.status(401).json({ message: "Not signed in." });

    const formerFriendIds = await friendService.removeAllFriends(user.user_id);

    // Live-refresh each former friend's friend list (and the user's own).
    for (const friendId of formerFriendIds) {
      broadcastToUser(friendId, { type: "friends_changed" });
    }
    broadcastToUser(user.user_id, { type: "friends_changed" });

    return res.json({ ok: true });
  } catch (err) {
    return next(err);
  }
}

async function blockUser(req, res, next) {
  try {
    const user = await requireAuth(req);
    if (!user) return res.status(401).json({ message: "Not signed in." });

    const result = await friendService.blockUser({
      userId: user.user_id,
      targetUserId: req.params.userId,
    });
    return res.json(result);
  } catch (err) {
    return next(err);
  }
}

async function unblockUser(req, res, next) {
  try {
    const user = await requireAuth(req);
    if (!user) return res.status(401).json({ message: "Not signed in." });

    const result = await friendService.unblockUser({
      userId: user.user_id,
      targetUserId: req.params.userId,
    });
    return res.json(result);
  } catch (err) {
    return next(err);
  }
}

module.exports = {
  acceptRequest,
  blockUser,
  cancelRequest,
  declineRequest,
  getBlocked,
  getBlockState,
  getFriends,
  getPending,
  purgeFriends,
  removeFriend,
  sendRequest,
  unblockUser,
};
