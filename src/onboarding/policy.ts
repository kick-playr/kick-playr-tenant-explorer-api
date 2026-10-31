import { environmentSchema, identifier, parse } from '../contracts.js';
export const ONBOARDING_POLICY = 'manager-setup-v1';
export function referenceDefaults(environment: string, tenantId: string) {
  parse(environmentSchema, environment);
  parse(identifier, tenantId);
  const prefix = (
    {
      development: 'workflow-local',
      preview: 'preview',
      production: 'prod',
      test: 'test',
    } as Record<string, string>
  )[environment];
  return {
    mongoUri: `${prefix}:${tenantId}:mongo`,
    key: `${prefix}:${tenantId}:key`,
  };
}
export function provisioningGuide(environment: string, tenantId: string) {
  const prefix = (
    {
      development: 'WORKFLOW_REAL',
      preview: 'PREVIEW',
      production: 'PROD',
      test: 'TEST',
    } as Record<string, string>
  )[environment];
  const variable = `${prefix}_${tenantId.replaceAll('-', '_').toUpperCase()}`;
  return {
    references: referenceDefaults(environment, tenantId),
    hsmSupported: false,
    proposedVariables: {
      wrapping: `${variable}_WRAPPING_KEY_V1`,
      index: `${variable}_INDEX_KEY`,
      control: `${variable}_CONTROL_KEY`,
    },
    steps: [
      {
        id: 'clerk',
        title: 'Clerk-Anwendung erstellen',
        instructions:
          'Clerk-Anwendung für diesen Verein und diese Umgebung manuell erstellen. APP-Origin und Weiterleitungen registrieren. Issuer und öffentlichen Schlüssel hinterlegen; Backend-Schlüssel nur serverseitig speichern.',
      },
      {
        id: 'claims',
        title: 'Session-Claims konfigurieren',
        instructions:
          'In Clerk die Session-Claims manuell setzen: aud muss die serverseitig konfigurierten Einrichtungs- und Betriebs-Audiences enthalten. Danach neu anmelden und die frische Session prüfen. Rollen und Kontakt-ID werden ausschliesslich serverseitig vergeben.',
      },
      {
        id: 'mongodb',
        title: 'MongoDB bereitstellen',
        instructions:
          'Vereinsdatenbank, eingeschränkten Datenbankbenutzer und Netzwerkzugriff manuell einrichten. URI serverseitig unter der Referenz speichern. Mit der bestehenden Runtime-Provisionierung die verschlüsselten Grundeinstellungen, Kataloge und echte vereinseigene Betriebsrichtlinie installieren; eine leere Datenbank reicht nicht aus. Keine Beispieldaten oder erfundenen Bexio-IDs verwenden. Bestehende Kontrolldatenbank wiederverwenden; Transaktionen benötigen Atlas oder ein Replica Set.',
      },
      {
        id: 'keys',
        title: 'Vereinsschlüssel erzeugen',
        instructions:
          "Für Wrapping, Index und Control je einen unabhängigen 32-Byte-Schlüssel erzeugen: node -e \"process.stdout.write(require('node:crypto').randomBytes(32).toString('base64'))\". Werte direkt im serverseitigen Secret-Speicher installieren. Vorhandene Schlüssel niemals ersetzen; Versionen für Entschlüsselung und Backups behalten.",
      },
      {
        id: 'custody',
        title: 'Schlüssel installieren',
        instructions:
          'Lokal: Schlüssel in die zugeordneten serverseitigen .env-Variablen kopieren; im Deployment Secret-Variablen verwenden. Keine privaten Werte in NEXT_PUBLIC_. HSM/KMS benötigt einen echten Adapter, Schlüsselreferenzen und geprüfte Berechtigungen. Nicht exportierbare HSM-Schlüssel bleiben im Provider; dieser Adapter ist derzeit nicht verfügbar.',
      },
      {
        id: 'email',
        title: 'Verbindungen prüfen und einladen',
        instructions:
          'Clerk, Claims, Datenbank, Schlüssel, Routing und Plattform-Mailversand serverseitig prüfen. Fehlende Voraussetzungen zuerst beheben; erst danach den ersten Manager über die bestehende Einladung einladen.',
      },
    ],
  };
}
