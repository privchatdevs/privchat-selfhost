const messageRepository = require("../repositories/messageRepository");

async function saveMessage({ senderId, receiverId, content, replyToMessageId = null, ttlSeconds = 0 }) {
  return messageRepository.saveMessage({ senderId, receiverId, content, replyToMessageId, ttlSeconds });
}

async function openConversationPair(userA, userB) {
  return messageRepository.openConversationPair(userA, userB);
}

async function getMessages(userA, userB, limit = 50, before = null) {
  return messageRepository.getMessages(userA, userB, limit, before);
}

async function getMessageById(messageId) {
  return messageRepository.getMessageById(messageId);
}

async function updateMessageContent({ messageId, senderId, receiverId, content }) {
  return messageRepository.updateMessageContent({ messageId, senderId, receiverId, content });
}

async function deleteMessage({ messageId, senderId, receiverId }) {
  return messageRepository.deleteMessage({ messageId, senderId, receiverId });
}

async function getReactionsForMessages(messageIds, currentUserId) {
  return messageRepository.getReactionsForMessages(messageIds, currentUserId);
}

async function toggleReaction({ messageId, userId, emoji }) {
  return messageRepository.toggleReaction({ messageId, userId, emoji });
}

function pinMessage({ messageId, userA, userB, pinnedBy }) {
  return messageRepository.pinMessage({ messageId, userA, userB, pinnedBy });
}

function unpinMessage({ messageId, userA, userB }) {
  return messageRepository.unpinMessage({ messageId, userA, userB });
}

function getPinnedMessages(userA, userB) {
  return messageRepository.getPinnedMessages(userA, userB);
}

async function getActiveConversations(userId) {
  return messageRepository.getActiveConversations(userId);
}

function markConversationRead(userId, partnerId) {
  return messageRepository.markConversationRead(userId, partnerId);
}

function setConversationPinned(userId, partnerId, pinned) {
  return messageRepository.setConversationPinned(userId, partnerId, pinned);
}

function getPinnedConversationIds(userId) {
  return messageRepository.getPinnedConversationIds(userId);
}

async function purgeConversation(userA, userB) {
  return messageRepository.purgeConversation(userA, userB);
}

function closeConversationPair(userA, userB) {
  return messageRepository.closeConversationPair(userA, userB);
}

function getConversationPartnerIds(userId) {
  return messageRepository.getConversationPartnerIds(userId);
}

// Wipe ALL of the user's DM messages and close every one of their threads.
async function purgeAllDms(userId) {
  await messageRepository.deleteAllDmMessagesForUser(userId);
  messageRepository.closeAllConversationsForUser(userId);
}

function hasAutoDeleteNoticeSince(senderId, receiverId, sinceIso) {
  return messageRepository.hasAutoDeleteNoticeSince(senderId, receiverId, sinceIso);
}

function listAutoDeleteNoticeReceivers(senderId, sinceIso) {
  return messageRepository.listAutoDeleteNoticeReceivers(senderId, sinceIso);
}

function deleteAutoDeleteNotices(senderId, receiverId) {
  return messageRepository.deleteAutoDeleteNotices(senderId, receiverId);
}

function getLatestAutoDeleteNotice(senderId, receiverId) {
  return messageRepository.getLatestAutoDeleteNotice(senderId, receiverId);
}

module.exports = {
  saveMessage,
  openConversationPair,
  getMessages,
  getMessageById,
  updateMessageContent,
  deleteMessage,
  getReactionsForMessages,
  toggleReaction,
  pinMessage,
  unpinMessage,
  getPinnedMessages,
  getActiveConversations,
  markConversationRead,
  setConversationPinned,
  getPinnedConversationIds,
  purgeConversation,
  closeConversationPair,
  getConversationPartnerIds,
  purgeAllDms,
  hasAutoDeleteNoticeSince,
  listAutoDeleteNoticeReceivers,
  getLatestAutoDeleteNotice,
  deleteAutoDeleteNotices,
};
