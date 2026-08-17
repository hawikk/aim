/* English catalog — source of truth for admin/analyst chrome.
 *
 * Scope of this file is the *critical* string surface:
 *  - severity / exposure bands (the product's primary axis)
 *  - nav + top-bar chrome
 *  - empty-state reasons (so a blank panel never reads as "clean")
 *  - security / findings / inbox operator language
 *  - shared format helpers that an analyst sees next to severity
 *
 * View-specific copy (overview cards, fleet table headers, …) migrates later.
 * v1 non-English catalogs: de / fr / nl (ship set, catalogs).
 * Do not add further locales until Security amends admin-ui-locales-v1.md
 * (remaining candidates live in LOCALES_AWAITING_SECURITY).
 *
 * Keys are stable API. Renaming a key is a breaking change for any locale
 * file; add aliases rather than rename in place.
 */

/** @type {Readonly<Record<string, unknown>>} */
export const en = Object.freeze({
  meta: {
    locale: 'en',
    name: 'English',
    direction: 'ltr',
  },

  chrome: {
    brand: 'AI Monitoring',
    skipToMain: 'Skip to main content',
    srDashboard: 'AI Monitoring usage dashboard',
    viewsLabel: 'Dashboard views',
    themeToLight: 'Switch to the light theme',
    themeToDark: 'Switch to the dark theme',
    themeLightLabel: 'Light theme',
    refresh: 'Refresh',
    rangeDays: '{days} days',
    liveStatus: 'Live status',
    noAccess: 'No dashboard access for this account.',
    hostsMissing: 'No collector reporting on {count} hosts.',
    locale: 'Language',
    localeHint: 'Interface language for admin and analyst chrome',
  },

  nav: {
    overview: 'Overview',
    security: 'Security',
    activity: 'Live',
    fleet: 'Fleet',
    analysis: 'Analysis',
    providers: 'Providers',
    appLlm: 'App-LLM',
    apps: 'Apps',
    teams: 'Teams',
    tools: 'Tools',
    repos: 'Repos',
    restricted: 'Restricted',
    users: 'Users',
    audit: 'Audit',
    findings: 'Findings',
    inbox: 'Alerts',
    rules: 'Rules',
    policy: 'Policy',
    runbooks: 'Runbooks',
    compliance: 'Compliance',
    mcp: 'MCP',
    coverage: 'Coverage',
    shadowAi: 'Shadow AI',
    onboarding: 'Onboarding',
    status: 'Status',
    cases: 'Cases',
    dashboards: 'Dashboards',
    installHealth: 'Install health',
  },

  /* Severity is the product's primary axis. Band *keys* stay English in
   * data-sev / CSS; these strings are the visible operator text. */
  severity: {
    band: {
      critical: 'critical',
      high: 'high',
      medium: 'medium',
      low: 'low',
      informational: 'informational',
    },
    srPrefix: 'Severity: ',
    title: {
      reported: 'Severity as reported by the detector on the matching events.',
      inferred: 'Inferred from the detection category — no event carried an explicit severity for this detector.',
    },
  },

  /* Exposure is reach, not risk — different words on purpose. */
  exposure: {
    wide: 'wide',
    moderate: 'moderate',
    contained: 'contained',
    unknown: 'unknown',
    rule: 'Derived from observed reach, not from any risk rating: '
      + 'wide = 10+ users or 3+ teams, moderate = 3+ users, contained = fewer.',
    unknownTitle: 'Reach cannot be computed: no event for this tool resolved to a user or team '
      + '(attribution gap). Volume is real; the spread is unmeasured.',
  },

  empty: {
    reason: {
      'no-data': {
        title: 'No data',
      },
      'no-collector': {
        title: 'No collector reporting',
        body: 'Nothing is being collected for this view, so an empty result here is not evidence of a clean result.',
      },
      filtered: {
        title: 'No rows match these filters',
        body: 'Data exists outside the current filters.',
      },
      error: {
        title: 'Could not load this panel',
        body: 'This panel is unknown, not empty. Do not read it as a clean result.',
      },
      loading: {
        title: 'Loading…',
      },
    },
    activeFilters: 'Active filters:',
    clearFilters: 'Clear filters',
    retry: 'Retry',
    setup: 'Setup:',
    openFleet: 'Open Fleet',
    openOnboarding: 'Open Onboarding',
  },

  /* Security view + findings/inbox operator language. Keep terse. */
  security: {
    title: 'Security',
    unapprovedTools: 'Unapproved tools',
    guardrailMatches: 'Guardrail matches',
    breakGlass: 'Break-glass overrides',
    mcpServers: 'MCP servers',
    openFindings: 'Open findings',
    criticalOpen: 'Critical open',
    unattributed: 'Unattributed',
    filterSeverity: 'Severity',
    filterAll: 'All severities',
  },

  findings: {
    title: 'Findings',
    inboxZero: 'Inbox zero — no open findings',
    noMatch: 'No findings match this filter',
    triage: 'Triage',
    open: 'Open',
    resolved: 'Resolved',
    acknowledged: 'Acknowledged',
  },

  inbox: {
    title: 'Alerts',
    empty: 'No alerts match these filters.',
    stackHealth: 'Stack health',
  },

  common: {
    loading: 'Loading…',
    error: 'Something went wrong',
    retry: 'Retry',
    cancel: 'Cancel',
    save: 'Save',
    close: 'Close',
    copy: 'Copy',
    copied: 'Copied',
    unknown: 'unknown',
    none: 'None',
    yes: 'Yes',
    no: 'No',
    all: 'All',
    search: 'Search',
    filter: 'Filter',
    export: 'Export',
    details: 'Details',
    actions: 'Actions',
  },

  format: {
    unattributed: 'unattributed',
    unknownSubject: 'unknown subject',
    user: 'user {ref}',
    host: 'host {ref}',
    repo: 'repo {ref}',
  },

  homeRole: {
    label: 'Home role',
    analyst: 'Analyst',
    admin: 'Admin',
    executive: 'Executive',
  },
});

export default en;
