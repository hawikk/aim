/* Dutch (nl) catalog — critical admin/analyst surface (AIM-917).
 *
 * Key tree mirrors locales/en.js. Severity / exposure / findings / inbox /
 * enforcement wording requires Security review before merge.
 * Language-only BCP-47 tag (not nl-NL) per docs/security/admin-ui-locales-v1.md.
 */

/** @type {Readonly<Record<string, unknown>>} */
export const nl = Object.freeze({
  meta: {
    locale: 'nl',
    name: 'Nederlands',
    direction: 'ltr',
  },

  chrome: {
    brand: 'AI Monitoring',
    skipToMain: 'Ga naar de hoofdinhoud',
    srDashboard: 'AI Monitoring gebruiks-dashboard',
    viewsLabel: 'Dashboardweergaven',
    themeToLight: 'Schakel naar het lichte thema',
    themeToDark: 'Schakel naar het donkere thema',
    themeLightLabel: 'Licht thema',
    refresh: 'Vernieuwen',
    rangeDays: '{days} dagen',
    liveStatus: 'Live status',
    noAccess: 'Geen dashboardtoegang voor dit account.',
    hostsMissing: 'Geen collector die rapporteert op {count} hosts.',
    locale: 'Taal',
    localeHint: 'Interfacetaal voor admin- en analisten-chrome',
  },

  nav: {
    overview: 'Overzicht',
    security: 'Beveiliging',
    activity: 'Live',
    fleet: 'Vloot',
    analysis: 'Analyse',
    providers: 'Providers',
    appLlm: 'App-LLM',
    apps: 'Apps',
    teams: 'Teams',
    tools: 'Tools',
    repos: 'Repos',
    restricted: 'Beperkt',
    users: 'Gebruikers',
    audit: 'Audit',
    findings: 'Findings',
    inbox: 'Alerts',
    rules: 'Regels',
    policy: 'Policy',
    runbooks: 'Runbooks',
    compliance: 'Compliance',
    mcp: 'MCP',
    coverage: 'Dekking',
    shadowAi: 'Shadow AI',
    onboarding: 'Onboarding',
    status: 'Status',
    cases: 'Cases',
    dashboards: 'Dashboards',
    installHealth: 'Installatiegezondheid',
  },

  /* Severity is the product's primary axis. Band *keys* stay English in
   * data-sev / CSS; these strings are the visible operator text. */
  severity: {
    band: {
      critical: 'kritiek',
      high: 'hoog',
      medium: 'gemiddeld',
      low: 'laag',
      informational: 'informatief',
    },
    srPrefix: 'Ernst: ',
    title: {
      reported: 'Ernst zoals gemeld door de detector op de bijbehorende events.',
      inferred: 'Afgeleid uit de detectiecategorie — geen event droeg een expliciete ernst voor deze detector.',
    },
  },

  /* Exposure is reach, not risk — different words on purpose (AIM-524). */
  exposure: {
    wide: 'breed',
    moderate: 'matig',
    contained: 'beperkt',
    unknown: 'onbekend',
    rule: 'Afgeleid van waargenomen bereik, niet van een risicoscore: '
      + 'breed = 10+ gebruikers of 3+ teams, matig = 3+ gebruikers, beperkt = minder.',
    unknownTitle: 'Bereik niet berekenbaar: geen event voor deze tool kon worden gekoppeld aan een gebruiker of team '
      + '(AIM-149 attributiegat). Volume is reëel; de spreiding is niet gemeten.',
  },

  empty: {
    reason: {
      'no-data': {
        title: 'Geen data',
      },
      'no-collector': {
        title: 'Geen collector die rapporteert',
        body: 'Voor deze weergave wordt niets verzameld — een leeg resultaat hier is geen bewijs van een schone staat.',
      },
      filtered: {
        title: 'Geen rijen komen overeen met deze filters',
        body: 'Er bestaan data buiten de huidige filters.',
      },
      error: {
        title: 'Dit paneel kon niet worden geladen',
        body: 'Dit paneel is onbekend, niet leeg. Lees het niet als een schoon resultaat.',
      },
      loading: {
        title: 'Laden…',
      },
    },
    activeFilters: 'Actieve filters:',
    clearFilters: 'Filters wissen',
    retry: 'Opnieuw proberen',
    setup: 'Setup:',
    openFleet: 'Vloot openen',
    openOnboarding: 'Onboarding openen',
  },

  /* Security view + findings/inbox operator language. Keep terse. */
  security: {
    title: 'Beveiliging',
    unapprovedTools: 'Niet-goedgekeurde tools',
    guardrailMatches: 'Guardrail-treffers',
    breakGlass: 'Break-glass-overrides',
    mcpServers: 'MCP-servers',
    openFindings: 'Open findings',
    criticalOpen: 'Kritiek open',
    unattributed: 'Niet geattribueerd',
    filterSeverity: 'Ernst',
    filterAll: 'Alle ernstniveaus',
  },

  findings: {
    title: 'Findings',
    inboxZero: 'Inbox leeg — geen open findings',
    noMatch: 'Geen findings komen overeen met dit filter',
    triage: 'Triage',
    open: 'Open',
    resolved: 'Opgelost',
    acknowledged: 'Bevestigd',
  },

  inbox: {
    title: 'Alerts',
    empty: 'Geen alerts komen overeen met deze filters.',
    stackHealth: 'Stackgezondheid',
  },

  common: {
    loading: 'Laden…',
    error: 'Er is iets misgegaan',
    retry: 'Opnieuw proberen',
    cancel: 'Annuleren',
    save: 'Opslaan',
    close: 'Sluiten',
    copy: 'Kopiëren',
    copied: 'Gekopieerd',
    unknown: 'onbekend',
    none: 'Geen',
    yes: 'Ja',
    no: 'Nee',
    all: 'Alles',
    search: 'Zoeken',
    filter: 'Filter',
    export: 'Exporteren',
    details: 'Details',
    actions: 'Acties',
  },

  format: {
    unattributed: 'niet geattribueerd',
    unknownSubject: 'onbekend subject',
    user: 'gebruiker {ref}',
    host: 'host {ref}',
    repo: 'repo {ref}',
  },

  homeRole: {
    label: 'Home-rol',
    analyst: 'Analist',
    admin: 'Admin',
    executive: 'Directie',
  },
});

export default nl;
