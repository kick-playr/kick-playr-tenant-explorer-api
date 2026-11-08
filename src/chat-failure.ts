/** Never relay upstream error text; admit only fixed chat reason codes and bounded cooldowns. */
export async function safeChatFailure(
  response: Response,
): Promise<{ message: string; chatReason?: string; retryAfter?: number }> {
  const fallback = {
    message:
      'Chat room/space operation needs review. Use the item’s Reconcile & retry control when a previous creation may exist.',
  };
  const reader = response.body?.getReader();
  if (!reader) return fallback;
  let length = 0;
  const chunks: Uint8Array[] = [];
  try {
    for (;;) {
      const part = await reader.read();
      if (part.done) break;
      length += part.value.length;
      if (length > 8192) return fallback;
      chunks.push(part.value);
    }
    const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    const messages: Record<string, string> = {
      'mapping-conflict':
        'Team Matrix mappings changed or conflict with the shared trainer group. Reload Matrix mappings and review before saving.',
      'legacy-conflict':
        'Existing seasons have conflicting room IDs. Review and explicitly confirm the desired mapping before saving.',
      'parent-missing':
        'Create the required parent space in Integrations → Chat rooms before linking this room.',
      'invalid-room':
        'The room ID is inaccessible, is a space, or belongs to another managed tenant or stage. Review the ID.',
      'reconciliation-required':
        'A previous creation record exists but the room alias is missing. Use Reconcile & retry for this item; no creation request was resent.',
      'orphan-detected':
        'A room without the expected alias may already exist. Review Matrix before retrying; no creation request was sent.',
      'unknown-outcome':
        'The creation outcome is unknown. Use Reconcile & retry before attempting another creation.',
      rejected:
        'Matrix rejected this operation. Review the administrator configuration before retrying.',
    };
    if (response.status === 429) {
      const delay =
        typeof body.retryAfter === 'number' && Number.isFinite(body.retryAfter)
          ? Math.max(1, Math.min(86400, Math.ceil(body.retryAfter)))
          : 1;
      return {
        message: `Matrix rate limited this operation. Retry after ${delay} seconds.`,
        chatReason: 'rate-limited',
        retryAfter: delay,
      };
    }
    if (
      typeof body.chatReason === 'string' &&
      Object.hasOwn(messages, body.chatReason)
    )
      return {
        message: messages[body.chatReason]!,
        chatReason: body.chatReason,
      };
    return fallback;
  } catch {
    return fallback;
  } finally {
    await reader.cancel().catch(() => {});
  }
}
