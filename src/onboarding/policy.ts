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
        description:
          'Eine eigene Anmeldung für diesen Verein und diese Umgebung einrichten.',
        actions: [
          'Im Clerk-Dashboard die Vereinsanwendung erstellen oder die passende vorhandene Anwendung auswählen.',
          'Die unten angezeigte APP-Origin und die benötigten Anmelde- und Rücksprung-URLs registrieren.',
          'Issuer und öffentlichen Schlüssel hinterlegen; den Backend-Schlüssel in der unten genannten serverseitigen Variable speichern.',
        ],
        title: 'Clerk-Anwendung erstellen',
        instructions:
          'Clerk-Anwendung für diesen Verein und diese Umgebung manuell erstellen. APP-Origin und Weiterleitungen registrieren. Issuer und öffentlichen Schlüssel hinterlegen; Backend-Schlüssel nur serverseitig speichern.',
      },
      {
        id: 'claims',
        description:
          'Die Session für Einrichtung und späteren Vereinsbetrieb korrekt kennzeichnen.',
        actions: [
          'In Clerk Sessions → Customize session token → Claims öffnen.',
          'Das unten angezeigte Claims-JSON übernehmen und speichern. Standard-Claims beibehalten; keine Rollen oder Kontakt-IDs ergänzen.',
          'Abmelden und neu anmelden, damit eine frische Session mit den neuen Audiences verwendet wird.',
        ],
        title: 'Session-Claims konfigurieren',
        instructions:
          'In Clerk die Session-Claims manuell setzen: aud muss die serverseitig konfigurierten Einrichtungs- und Betriebs-Audiences enthalten. Danach neu anmelden und die frische Session prüfen. Rollen und Kontakt-ID werden ausschliesslich serverseitig vergeben.',
      },
      {
        id: 'mongodb',
        description:
          'Eine eigene Vereinsdatenbank vorbereiten und ihre Verbindung verschlüsselt hinterlegen.',
        actions: [
          'Datenbank, Datenbankbenutzer und Netzwerkzugriff im konfigurierten MongoDB-Cluster einrichten. Die vorhandene Kontrolldatenbank weiterverwenden.',
          'Die vollständige URL oben unter MongoDB-Verbindung eingeben und verschlüsselt speichern.',
          'Die vollständige Runtime-Registrierung, verschlüsselten Grundeinstellungen, Kataloge und echte Vereinsrichtlinie bereitstellen. Ein URL-Entwurf oder eine leere Datenbank reicht nicht aus.',
        ],
        title: 'MongoDB bereitstellen',
        instructions:
          'Vereinsdatenbank, eingeschränkten Datenbankbenutzer und Netzwerkzugriff manuell einrichten. Die vollständige MongoDB-URL im Onboarding-Feld MongoDB-URL eingeben und verschlüsselt speichern. Ohne vollständige Runtime-Registrierung bleibt sie ein Vorbereitungsentwurf. Mit der bestehenden Runtime-Provisionierung die verschlüsselten Grundeinstellungen, Kataloge und echte vereinseigene Betriebsrichtlinie installieren; eine leere Datenbank reicht nicht aus. Keine Beispieldaten oder erfundenen Bexio-IDs verwenden. Bestehende Kontrolldatenbank wiederverwenden; Transaktionen benötigen Atlas oder ein Replica Set.',
      },
      {
        id: 'keys',
        description:
          'Drei unabhängige Schlüssel für Wrapping, Index und Control erzeugen.',
        actions: [
          `Im Tenant-API-Verzeichnis ausführen: ./create-key.sh ${environment === 'development' ? 'workflow-local:' + tenantId : variable}`,
          'Die drei ausgegebenen Werte für WRAPPING_KEY_V1, INDEX_KEY und CONTROL_KEY getrennt übernehmen.',
          'Bei bereits verschlüsselten Daten die bestehenden Schlüssel behalten und keine Ersatzwerte erzeugen.',
        ],
        title: 'Vereinsschlüssel erzeugen',
        instructions:
          "Für Wrapping, Index und Control je einen unabhängigen 32-Byte-Schlüssel erzeugen: node -e \"process.stdout.write(require('node:crypto').randomBytes(32).toString('base64'))\". Werte direkt im serverseitigen Secret-Speicher installieren. Vorhandene Schlüssel niemals ersetzen; Versionen für Entschlüsselung und Backups behalten.",
      },
      {
        id: 'custody',
        description:
          'Die Schlüssel unter den zugeordneten Variablennamen auf beiden APIs installieren.',
        actions: [
          'Die unten angezeigten Variablen in der serverseitigen .env der Tenant-API und der Runtime-API anlegen und die jeweiligen Schlüsselwerte einsetzen.',
          'Im Deployment Secret-Variablen verwenden. Der aktuelle Adapter bietet keine HSM/KMS-Anbindung; Schlüssel niemals in NEXT_PUBLIC_-Variablen ablegen.',
        ],
        title: 'Schlüssel installieren',
        instructions:
          'Lokal: Schlüssel in die zugeordneten serverseitigen .env-Variablen kopieren; im Deployment Secret-Variablen verwenden. Keine privaten Werte in NEXT_PUBLIC_. HSM/KMS benötigt einen echten Adapter, Schlüsselreferenzen und geprüfte Berechtigungen. Nicht exportierbare HSM-Schlüssel bleiben im Provider; dieser Adapter ist derzeit nicht verfügbar.',
      },
      {
        id: 'email',
        description:
          'Die technischen Voraussetzungen bestätigen und den ersten Manager einladen.',
        actions: [
          'Plattform-SMTP und Absender für den Einladungsversand konfigurieren.',
          'Unten Verbindungen prüfen wählen und gemeldete fehlende Voraussetzungen beheben. Die Prüfung allein sendet keine Einladung.',
          'Erst nach erfolgreicher Prüfung den ersten Manager als Owner einladen. Er muss das Onboarding abschliessen, bevor weitere Manager folgen.',
        ],
        title: 'Verbindungen prüfen und einladen',
        instructions:
          'Clerk, Claims, Datenbank, Schlüssel, Routing und Plattform-Mailversand serverseitig prüfen. Fehlende Voraussetzungen zuerst beheben; erst danach den ersten Manager über die bestehende Einladung einladen.',
      },
    ],
  };
}
