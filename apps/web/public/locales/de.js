/* German (de) catalog — critical admin/analyst surface.
 *
 * Key tree mirrors locales/en.js. Severity / exposure / findings / inbox /
 * enforcement wording requires Security review before merge.
 * Language-only BCP-47 tag (not de-DE) per docs/security/admin-ui-locales-v1.md.
 */

/** @type {Readonly<Record<string, unknown>>} */
export const de = Object.freeze({
  meta: {
    locale: 'de',
    name: 'Deutsch',
    direction: 'ltr',
  },

  chrome: {
    brand: 'AI Monitoring',
    skipToMain: 'Zum Hauptinhalt springen',
    srDashboard: 'AI-Monitoring Nutzungs-Dashboard',
    viewsLabel: 'Dashboard-Ansichten',
    themeToLight: 'Zum hellen Design wechseln',
    themeToDark: 'Zum dunklen Design wechseln',
    themeLightLabel: 'Helles Design',
    refresh: 'Aktualisieren',
    rangeDays: '{days} Tage',
    liveStatus: 'Live-Status',
    noAccess: 'Kein Dashboard-Zugriff für dieses Konto.',
    hostsMissing: 'Kein Collector meldet auf {count} Hosts.',
    locale: 'Sprache',
    localeHint: 'Oberflächensprache für Admin- und Analysten-Chrome',
  },

  nav: {
    overview: 'Übersicht',
    security: 'Security',
    activity: 'Live',
    fleet: 'Flotte',
    analysis: 'Analyse',
    providers: 'Anbieter',
    appLlm: 'App-LLM',
    apps: 'Apps',
    teams: 'Teams',
    tools: 'Tools',
    repos: 'Repos',
    restricted: 'Eingeschränkt',
    users: 'Benutzer',
    audit: 'Audit',
    findings: 'Findings',
    inbox: 'Alerts',
    rules: 'Regeln',
    policy: 'Policy',
    runbooks: 'Runbooks',
    compliance: 'Compliance',
    mcp: 'MCP',
    coverage: 'Abdeckung',
    shadowAi: 'Shadow AI',
    onboarding: 'Onboarding',
    status: 'Status',
    cases: 'Fälle',
    dashboards: 'Dashboards',
    installHealth: 'Installationsstatus',
  },

  /* Severity is the product's primary axis. Band *keys* stay English in
   * data-sev / CSS; these strings are the visible operator text. */
  severity: {
    band: {
      critical: 'kritisch',
      high: 'hoch',
      medium: 'mittel',
      low: 'niedrig',
      informational: 'informativ',
    },
    srPrefix: 'Schweregrad: ',
    title: {
      reported: 'Schweregrad laut Detektor auf den zugehörigen Ereignissen.',
      inferred: 'Aus der Erkennungskategorie abgeleitet — kein Ereignis trug einen expliziten Schweregrad für diesen Detektor.',
    },
  },

  /* Exposure is reach, not risk — different words on purpose. */
  exposure: {
    wide: 'weit',
    moderate: 'mäßig',
    contained: 'begrenzt',
    unknown: 'unbekannt',
    rule: 'Abgeleitet aus beobachteter Reichweite, nicht aus einer Risikobewertung: '
      + 'weit = 10+ Benutzer oder 3+ Teams, mäßig = 3+ Benutzer, begrenzt = weniger.',
    unknownTitle: 'Reichweite nicht berechenbar: kein Ereignis für dieses Tool ließ sich einem Benutzer oder Team zuordnen '
      + '(Attributionslücke). Volumen ist real; die Verbreitung ist ungemessen.',
  },

  empty: {
    reason: {
      'no-data': {
        title: 'Keine Daten',
      },
      'no-collector': {
        title: 'Kein Collector meldet',
        body: 'Für diese Ansicht wird nichts erfasst — ein leeres Ergebnis ist hier kein Beleg für einen sauberen Zustand.',
      },
      filtered: {
        title: 'Keine Zeilen entsprechen diesen Filtern',
        body: 'Außerhalb der aktuellen Filter liegen Daten vor.',
      },
      error: {
        title: 'Panel konnte nicht geladen werden',
        body: 'Dieses Panel ist unbekannt, nicht leer. Nicht als sauberes Ergebnis lesen.',
      },
      loading: {
        title: 'Laden…',
      },
    },
    activeFilters: 'Aktive Filter:',
    clearFilters: 'Filter zurücksetzen',
    retry: 'Erneut versuchen',
    setup: 'Setup:',
    openFleet: 'Flotte öffnen',
    openOnboarding: 'Onboarding öffnen',
  },

  /* Security view + findings/inbox operator language. Keep terse. */
  security: {
    title: 'Security',
    unapprovedTools: 'Nicht freigegebene Tools',
    guardrailMatches: 'Guardrail-Treffer',
    breakGlass: 'Break-Glass-Overrides',
    mcpServers: 'MCP-Server',
    openFindings: 'Offene Findings',
    criticalOpen: 'Kritisch offen',
    unattributed: 'Nicht attribuiert',
    filterSeverity: 'Schweregrad',
    filterAll: 'Alle Schweregrade',
  },

  findings: {
    title: 'Findings',
    inboxZero: 'Inbox leer — keine offenen Findings',
    noMatch: 'Keine Findings entsprechen diesem Filter',
    triage: 'Triage',
    open: 'Offen',
    resolved: 'Erledigt',
    acknowledged: 'Bestätigt',
  },

  inbox: {
    title: 'Alerts',
    empty: 'Keine Alerts entsprechen diesen Filtern.',
    stackHealth: 'Stack-Gesundheit',
  },

  common: {
    loading: 'Laden…',
    error: 'Etwas ist schiefgelaufen',
    retry: 'Erneut versuchen',
    cancel: 'Abbrechen',
    save: 'Speichern',
    close: 'Schließen',
    copy: 'Kopieren',
    copied: 'Kopiert',
    unknown: 'unbekannt',
    none: 'Keine',
    yes: 'Ja',
    no: 'Nein',
    all: 'Alle',
    search: 'Suchen',
    filter: 'Filter',
    export: 'Exportieren',
    details: 'Details',
    actions: 'Aktionen',
  },

  format: {
    unattributed: 'nicht attribuiert',
    unknownSubject: 'unbekanntes Subjekt',
    user: 'Benutzer {ref}',
    host: 'Host {ref}',
    repo: 'Repo {ref}',
  },

  homeRole: {
    label: 'Home-Rolle',
    analyst: 'Analyst',
    admin: 'Admin',
    executive: 'Führung',
  },
});

export default de;
