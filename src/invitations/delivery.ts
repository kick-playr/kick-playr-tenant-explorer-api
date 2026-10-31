import { createRequire } from 'node:module';
import type { DeliveryPort } from './types.js';
/** Explicit platform sender, independent of the unprovisioned club's SMTP. */
export function invitationSender(
  env: Record<string, string | undefined>,
): DeliveryPort {
  if (!env.EXPLORER_INVITATION_SMTP_URL || !env.EXPLORER_INVITATION_FROM)
    return {
      ready: false,
      send: async () => {
        throw Error('Invitation email unavailable');
      },
    };
  const url = new URL(env.EXPLORER_INVITATION_SMTP_URL);
  if (url.protocol !== 'smtps:')
    throw Error('Invitation sender requires SMTPS');
  const mail = createRequire(import.meta.url)('nodemailer') as {
    createTransport: (o: object) => {
      sendMail: (
        m: object,
      ) => Promise<{ accepted?: string[]; rejected?: string[] }>;
    };
  };
  const transport = mail.createTransport({
    host: url.hostname,
    port: Number(url.port || 465),
    secure: true,
    auth: {
      user: decodeURIComponent(url.username),
      pass: decodeURIComponent(url.password),
    },
    connectionTimeout: 10000,
    greetingTimeout: 10000,
    socketTimeout: 20000,
  });
  const from = env.EXPLORER_INVITATION_FROM;
  if (!/^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(from))
    throw Error('Invalid invitation sender');
  return {
    ready: true,
    async send(m) {
      const result = await transport.sendMail({
        from,
        to: m.to,
        messageId: `<invitation-${m.id.replace(':', '-')}@${from.split('@')[1]}>`,
        subject: 'Einladung als Vereinsmanager',
        text: `Sie wurden eingeladen, ${m.club} zu verwalten. Melden Sie sich mit Ihrem eingeladenen Konto an und nehmen Sie die Einladung an. Der Link ist sieben Tage gültig.\n\n${m.url}`,
      });
      if (result.rejected?.length || !result.accepted?.length)
        throw Error('Invitation delivery not accepted');
    },
  };
}
