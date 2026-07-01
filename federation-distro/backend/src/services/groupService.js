const groupRepository = require("../repositories/groupRepository");
const friendRepository = require("../repositories/friendRepository");
const userRepository = require("../repositories/userRepository");
const b2Storage = require("./b2Storage");
const assetService = require("./assetService");

const { MAX_GROUP_MEMBERS } = groupRepository;
const MAX_NAME_LEN = 32;

// Are these two INTERNAL ids accepted friends?
function areFriends(a, b) {
  const f = friendRepository.getFriendship(a, b);
  return Boolean(f && f.status === "accepted");
}

// Resolve a list of PUBLIC ids to distinct internal user rows, dropping unknowns
// and the caller themselves. Returns [{ user }] preserving uniqueness.
function resolveUsers(publicIds, excludeInternalId) {
  const seen = new Set();
  const out = [];
  for (const pid of Array.isArray(publicIds) ? publicIds : []) {
    const u = userRepository.findByAnyId(String(pid));
    if (!u) continue;
    if (u.user_id === excludeInternalId) continue;
    if (seen.has(u.user_id)) continue;
    seen.add(u.user_id);
    out.push(u);
  }
  return out;
}

function sanitizeName(name) {
  if (typeof name !== "string") return null;
  const trimmed = name.trim().slice(0, MAX_NAME_LEN);
  return trimmed || null;
}

// Public id / display name for an internal user row (mirrors the controller's
// public mapping). Used to build plaintext system notices.
function publicId(u) {
  return u.public_user_id || u.user_id;
}
function displayName(u) {
  return u.profile_alias || u.username || "Someone";
}

// Persist a plaintext "system" notice (e.g. "X added Y"). These are NOT E2E
// encrypted - they carry no private content, only who did what - so every
// member, including people added later, can render them. The client recognizes
// the _gsys marker and renders a centered notice instead of a chat bubble.
function saveSystemMessage(groupId, actor, kind, targets) {
  const content = JSON.stringify({
    _gsys: 1,
    kind,
    by: publicId(actor),
    byName: displayName(actor),
    targets: targets.map((u) => ({ id: publicId(u), name: displayName(u) })),
  });
  return groupRepository.saveMessage({ groupId, senderId: actor.user_id, content });
}

// Create a group. The creator must add at least two of their accepted friends
// (a group chat needs 3+ people; one-on-one is a direct message), and every
// invitee must be a friend of the creator. Total members (creator included)
// can't exceed MAX_GROUP_MEMBERS.
// Returns { ok, groupId } or { ok:false, error }.
function createGroup({ owner, memberPublicIds, name }) {
  const invitees = resolveUsers(memberPublicIds, owner.user_id);
  if (invitees.length < 2) {
    return { ok: false, status: 400, error: "A group chat needs at least 3 people. Add 2 or more friends - for just one person, use a direct message." };
  }
  for (const u of invitees) {
    if (!areFriends(owner.user_id, u.user_id)) {
      return { ok: false, status: 403, error: "You can only add your friends to a group chat." };
    }
  }
  if (invitees.length + 1 > MAX_GROUP_MEMBERS) {
    return { ok: false, status: 400, error: `A group chat can have at most ${MAX_GROUP_MEMBERS} people.` };
  }

  const groupId = groupRepository.createGroup({ ownerId: owner.user_id, name: sanitizeName(name) });
  groupRepository.addMember(groupId, owner.user_id);
  for (const u of invitees) groupRepository.addMember(groupId, u.user_id);
  return { ok: true, groupId, addedInternalIds: invitees.map((u) => u.user_id) };
}

// Add more people to an existing group. The actor must be a member, every new
// person must be the ACTOR's friend, and the cap still applies.
// Returns { ok, addedInternalIds } or { ok:false, error }.
function addMembers({ group, actor, memberPublicIds }) {
  if (!groupRepository.isMember(group.group_id, actor.user_id)) {
    return { ok: false, status: 403, error: "You're not in this group chat." };
  }
  const candidates = resolveUsers(memberPublicIds, actor.user_id)
    .filter((u) => !groupRepository.isMember(group.group_id, u.user_id));
  if (candidates.length === 0) {
    return { ok: false, status: 400, error: "No one new to add." };
  }
  for (const u of candidates) {
    if (!areFriends(actor.user_id, u.user_id)) {
      return { ok: false, status: 403, error: "You can only add your friends to a group chat." };
    }
  }
  if (groupRepository.countMembers(group.group_id) + candidates.length > MAX_GROUP_MEMBERS) {
    return { ok: false, status: 400, error: `A group chat can have at most ${MAX_GROUP_MEMBERS} people.` };
  }
  for (const u of candidates) groupRepository.addMember(group.group_id, u.user_id);
  // Drop an "<actor> added <names>" notice into the chat for everyone.
  const systemMessage = saveSystemMessage(group.group_id, actor, "add", candidates);
  groupRepository.touchGroup(group.group_id);
  return { ok: true, addedInternalIds: candidates.map((u) => u.user_id), systemMessage };
}

// Remove yourself or (owner only) someone else. If the group empties or the owner
// leaves, ownership transfers to the oldest remaining member; an empty group is
// deleted. Returns { ok, remainingIds, deleted, removedInternalId }.
function removeMember({ group, actor, targetInternalId }) {
  const isSelf = targetInternalId === actor.user_id;
  if (!isSelf && group.owner_id !== actor.user_id) {
    return { ok: false, status: 403, error: "Only the group owner can remove people." };
  }
  if (!groupRepository.isMember(group.group_id, targetInternalId)) {
    return { ok: false, status: 404, error: "That person isn't in this group." };
  }
  const targetUser = userRepository.findById(targetInternalId);

  groupRepository.removeMember(group.group_id, targetInternalId);
  const remaining = groupRepository.getMemberIds(group.group_id);
  if (remaining.length === 0) {
    groupRepository.deleteGroup(group.group_id);
    return { ok: true, remainingIds: [], deleted: true, removedInternalId: targetInternalId };
  }
  // Hand ownership to the oldest remaining member if the owner left.
  if (group.owner_id === targetInternalId && !remaining.includes(group.owner_id)) {
    const oldest = groupRepository.getMembers(group.group_id)[0];
    if (oldest) groupRepository.setOwner(group.group_id, oldest.user_id);
  }
  // Drop a system notice for everyone: "<owner> removed <name>" for a kick, or
  // "<name> left" when someone leaves on their own.
  const systemMessage = isSelf
    ? saveSystemMessage(group.group_id, actor, "leave", [])
    : (targetUser ? saveSystemMessage(group.group_id, actor, "remove", [targetUser]) : null);
  groupRepository.touchGroup(group.group_id);
  return { ok: true, remainingIds: remaining, deleted: false, removedInternalId: targetInternalId, systemMessage };
}

// Owner-only: delete the whole group for everyone. Returns the member ids that
// were in it (so the controller can notify each of them) or an error.
function deleteGroup({ group, actor }) {
  if (group.owner_id !== actor.user_id) {
    return { ok: false, status: 403, error: "Only the group owner can delete the group." };
  }
  const memberIds = groupRepository.getMemberIds(group.group_id);
  groupRepository.deleteGroup(group.group_id);
  return { ok: true, memberIds };
}

// Owner-only: wipe every message in the group while keeping the group + members.
// Batched so a huge history can't freeze the process; also hard-deletes the
// group's uploaded files (best-effort). Returns the member ids to notify.
async function purgeGroupMessages({ group, actor }) {
  if (group.owner_id !== actor.user_id) {
    return { ok: false, status: 403, error: "Only the group owner can purge the chat." };
  }
  const memberIds = groupRepository.getMemberIds(group.group_id);
  await groupRepository.deleteGroupMessagesInBatches(group.group_id);
  try { await assetService.purgeGroupAssets(group.group_id); } catch { /* best-effort file cleanup */ }
  groupRepository.touchGroup(group.group_id);
  return { ok: true, memberIds };
}

// Owner-only: hand ownership to another current member. Returns { ok } or an error.
function transferOwnership({ group, actor, targetInternalId }) {
  if (group.owner_id !== actor.user_id) {
    return { ok: false, status: 403, error: "Only the group owner can transfer ownership." };
  }
  if (targetInternalId === actor.user_id) {
    return { ok: false, status: 400, error: "You're already the owner." };
  }
  if (!groupRepository.isMember(group.group_id, targetInternalId)) {
    return { ok: false, status: 404, error: "That person isn't in this group." };
  }
  groupRepository.setOwner(group.group_id, targetInternalId);
  groupRepository.touchGroup(group.group_id);
  return { ok: true };
}

// Auto-delete groups that have gone INACTIVE_GROUP_TTL_DAYS without a new message.
// Fully purges every trace - messages (batched), members, the group row, and its
// stored icon. Internal housekeeping run by the auto-delete sweeper: silent by
// design (no user notification, nothing logged about what was removed). Capped per
// run; a backlog is cleared over subsequent sweeps. Returns the count handled.
async function sweepInactiveGroups() {
  const stale = groupRepository.getInactiveGroups(200);
  for (const g of stale) {
    await groupRepository.deleteGroupMessagesInBatches(g.group_id);
    groupRepository.deleteGroup(g.group_id); // messages already gone; clears members + row
    await assetService.purgeGroupAssets(g.group_id); // hard-delete every uploaded file in it
    if (g.icon_key) {
      try { await b2Storage.deleteMedia(g.icon_key); } catch { /* best-effort B2 cleanup */ }
    }
  }
  return stale.length;
}

// Remove a user from every group they're in and delete only THEIR authored
// messages (the rest of each group's history stays). If a group empties out it is
// fully purged (messages, members, row, uploaded files, icon); if the leaving user
// owned a still-populated group, ownership passes to a RANDOM remaining member.
// Used by account deletion and "purge my DMs". The caller separately wipes the
// user's own uploaded files everywhere via assetService.purgeOwnerAssets.
// Returns { leftGroupIds, survivingGroupIds }: every group the user was in, and
// the subset that still exists afterwards (so the caller can refresh those groups'
// remaining members - member count + the possibly-new owner).
async function purgeUserFromAllGroups(userInternalId) {
  const leftGroupIds = groupRepository.getGroupIdsForUser(userInternalId);
  const survivingGroupIds = [];
  for (const groupId of leftGroupIds) {
    const group = groupRepository.getGroup(groupId);
    if (!group) continue;
    await groupRepository.deleteUserMessagesInGroup(groupId, userInternalId);
    groupRepository.removeMember(groupId, userInternalId);
    const remaining = groupRepository.getMemberIds(groupId);
    if (remaining.length === 0) {
      await groupRepository.deleteGroupMessagesInBatches(groupId);
      groupRepository.deleteGroup(groupId);
      await assetService.purgeGroupAssets(groupId);
      if (group.icon_key) {
        try { await b2Storage.deleteMedia(group.icon_key); } catch { /* best-effort */ }
      }
      continue;
    }
    // Owner left: hand ownership to a random remaining member.
    if (group.owner_id === userInternalId) {
      const heir = remaining[Math.floor(Math.random() * remaining.length)];
      if (heir) groupRepository.setOwner(groupId, heir);
    }
    survivingGroupIds.push(groupId);
  }
  return { leftGroupIds, survivingGroupIds };
}

// Delete only THIS user's authored messages across every group they're in, leaving
// their membership and everyone else's messages intact. Used by the forgot-password
// reset: the user's E2E group messages were sealed under their old key (wiped on
// reset), so their own ciphertext can no longer be decrypted - purge it instead of
// leaving undecryptable junk, exactly like the reset already does for DMs. Other
// members' messages are never touched.
async function clearUserGroupMessages(userInternalId) {
  const groupIds = groupRepository.getGroupIdsForUser(userInternalId);
  for (const groupId of groupIds) {
    await groupRepository.deleteUserMessagesInGroup(groupId, userInternalId);
  }
  return groupIds;
}

function rename({ group, actor, name }) {
  if (!groupRepository.isMember(group.group_id, actor.user_id)) {
    return { ok: false, status: 403, error: "You're not in this group chat." };
  }
  groupRepository.renameGroup(group.group_id, sanitizeName(name));
  return { ok: true };
}

// Persist an E2E ciphertext message. The caller has already verified membership.
function sendMessage({ groupId, senderInternalId, content, replyToMessageId, ttlSeconds = 0 }) {
  return groupRepository.saveMessage({
    groupId,
    senderId: senderInternalId,
    content,
    replyToMessageId: replyToMessageId || null,
    ttlSeconds,
  });
}

module.exports = {
  MAX_GROUP_MEMBERS,
  createGroup,
  addMembers,
  removeMember,
  deleteGroup,
  purgeGroupMessages,
  transferOwnership,
  sweepInactiveGroups,
  purgeUserFromAllGroups,
  clearUserGroupMessages,
  rename,
  sendMessage,
  areFriends,
};
