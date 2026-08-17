/* French (fr) catalog — critical admin/analyst surface.
 *
 * Key tree mirrors locales/en.js. Severity / exposure / findings / inbox /
 * enforcement wording requires Security review before merge.
 * Language-only BCP-47 tag (not fr-FR) per docs/security/admin-ui-locales-v1.md.
 */

/** @type {Readonly<Record<string, unknown>>} */
export const fr = Object.freeze({
  meta: {
    locale: 'fr',
    name: 'Français',
    direction: 'ltr',
  },

  chrome: {
    brand: 'AI Monitoring',
    skipToMain: 'Aller au contenu principal',
    srDashboard: 'Tableau de bord d’usage AI Monitoring',
    viewsLabel: 'Vues du tableau de bord',
    themeToLight: 'Passer au thème clair',
    themeToDark: 'Passer au thème sombre',
    themeLightLabel: 'Thème clair',
    refresh: 'Actualiser',
    rangeDays: '{days} jours',
    liveStatus: 'État en direct',
    noAccess: 'Aucun accès au tableau de bord pour ce compte.',
    hostsMissing: 'Aucun collecteur ne remonte sur {count} hôtes.',
    locale: 'Langue',
    localeHint: 'Langue de l’interface admin / analyste',
  },

  nav: {
    overview: 'Vue d’ensemble',
    security: 'Sécurité',
    activity: 'Live',
    fleet: 'Flotte',
    analysis: 'Analyse',
    providers: 'Fournisseurs',
    appLlm: 'App-LLM',
    apps: 'Apps',
    teams: 'Équipes',
    tools: 'Outils',
    repos: 'Dépôts',
    restricted: 'Restreint',
    users: 'Utilisateurs',
    audit: 'Audit',
    findings: 'Findings',
    inbox: 'Alertes',
    rules: 'Règles',
    policy: 'Politique',
    runbooks: 'Runbooks',
    compliance: 'Conformité',
    mcp: 'MCP',
    coverage: 'Couverture',
    shadowAi: 'Shadow AI',
    onboarding: 'Onboarding',
    status: 'Statut',
    cases: 'Dossiers',
    dashboards: 'Tableaux de bord',
    installHealth: 'Santé d’installation',
  },

  /* Severity is the product's primary axis. Band *keys* stay English in
   * data-sev / CSS; these strings are the visible operator text. */
  severity: {
    band: {
      critical: 'critique',
      high: 'élevé',
      medium: 'moyen',
      low: 'faible',
      informational: 'informationnel',
    },
    srPrefix: 'Sévérité : ',
    title: {
      reported: 'Sévérité telle que signalée par le détecteur sur les événements correspondants.',
      inferred: 'Inférée à partir de la catégorie de détection — aucun événement ne portait une sévérité explicite pour ce détecteur.',
    },
  },

  /* Exposure is reach, not risk — different words on purpose. */
  exposure: {
    wide: 'large',
    moderate: 'modérée',
    contained: 'contenue',
    unknown: 'inconnue',
    rule: 'Dérivée de la portée observée, non d’une note de risque : '
      + 'large = 10+ utilisateurs ou 3+ équipes, modérée = 3+ utilisateurs, contenue = moins.',
    unknownTitle: 'Portée non calculable : aucun événement pour cet outil n’a pu être rattaché à un utilisateur ou une équipe '
      + '(lacune d’attribution). Le volume est réel; la diffusion n’est pas mesurée.',
  },

  empty: {
    reason: {
      'no-data': {
        title: 'Aucune donnée',
      },
      'no-collector': {
        title: 'Aucun collecteur ne remonte',
        body: 'Rien n’est collecté pour cette vue — un résultat vide ici n’est pas la preuve d’un état sain.',
      },
      filtered: {
        title: 'Aucune ligne ne correspond à ces filtres',
        body: 'Des données existent en dehors des filtres actuels.',
      },
      error: {
        title: 'Impossible de charger ce panneau',
        body: 'Ce panneau est inconnu, pas vide. Ne pas le lire comme un résultat propre.',
      },
      loading: {
        title: 'Chargement…',
      },
    },
    activeFilters: 'Filtres actifs :',
    clearFilters: 'Effacer les filtres',
    retry: 'Réessayer',
    setup: 'Configuration :',
    openFleet: 'Ouvrir la flotte',
    openOnboarding: 'Ouvrir l’onboarding',
  },

  /* Security view + findings/inbox operator language. Keep terse. */
  security: {
    title: 'Sécurité',
    unapprovedTools: 'Outils non approuvés',
    guardrailMatches: 'Correspondances de garde-fou',
    breakGlass: 'Dérogations break-glass',
    mcpServers: 'Serveurs MCP',
    openFindings: 'Findings ouverts',
    criticalOpen: 'Critiques ouverts',
    unattributed: 'Non attribué',
    filterSeverity: 'Sévérité',
    filterAll: 'Toutes les sévérités',
  },

  findings: {
    title: 'Findings',
    inboxZero: 'Boîte vide — aucun finding ouvert',
    noMatch: 'Aucun finding ne correspond à ce filtre',
    triage: 'Triage',
    open: 'Ouvert',
    resolved: 'Résolu',
    acknowledged: 'Acquitté',
  },

  inbox: {
    title: 'Alertes',
    empty: 'Aucune alerte ne correspond à ces filtres.',
    stackHealth: 'Santé de la stack',
  },

  common: {
    loading: 'Chargement…',
    error: 'Une erreur s’est produite',
    retry: 'Réessayer',
    cancel: 'Annuler',
    save: 'Enregistrer',
    close: 'Fermer',
    copy: 'Copier',
    copied: 'Copié',
    unknown: 'inconnu',
    none: 'Aucun',
    yes: 'Oui',
    no: 'Non',
    all: 'Tous',
    search: 'Rechercher',
    filter: 'Filtrer',
    export: 'Exporter',
    details: 'Détails',
    actions: 'Actions',
  },

  format: {
    unattributed: 'non attribué',
    unknownSubject: 'sujet inconnu',
    user: 'utilisateur {ref}',
    host: 'hôte {ref}',
    repo: 'dépôt {ref}',
  },

  homeRole: {
    label: 'Rôle d’accueil',
    analyst: 'Analyste',
    admin: 'Admin',
    executive: 'Direction',
  },
});

export default fr;
