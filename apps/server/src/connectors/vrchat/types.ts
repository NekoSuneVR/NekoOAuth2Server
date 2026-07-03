/**
 * The subset of the VRChat API this module needs, abstracted behind an
 * interface so the verification logic (verification.ts) can be tested
 * against a fake implementation — there's no real VRChat bot account
 * available to test against in this environment, but the polling/timeout/
 * decision logic underneath doesn't need one to be verified correctly.
 */
export interface VRChatBotClient {
  getUserById(userId: string): Promise<{ id: string; bio: string }>;
  sendFriendRequest(userId: string): Promise<void>;
  getFriendStatus(userId: string): Promise<{ isFriend: boolean; outgoingRequest: boolean }>;
  deleteFriendRequest(userId: string): Promise<void>;
  unfriend(userId: string): Promise<void>;
}
