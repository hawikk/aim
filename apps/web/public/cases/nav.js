/* List ↔ detail pane navigation for the Cases view (AIM-1186 split).
 * Owns the hash-driven pane switch so list.js and detail.js never import
 * each other: both import goCase/goList from here, and this module imports
 * the pane renderers one-directionally. */

import { parseHash, hashFor, setHash } from '../lib/router.js';
import { emptyState } from '../lib/components.js';
import { casesCtx } from './state.js';
import { showList } from './list.js';
import { showDetail } from './detail.js';

/* Module-view activation: drill hash (#/cases/<id>) opens the detail pane,
 * anything else the list. Returned promise lets the orchestrator surface an
 * activation failure in the list pane. */
export async function activate() {
  const { entity } = parseHash(location.hash);
  if (entity) await showDetail(entity);
  else await showList();
}

export function goCase(caseId) {
  const hash = hashFor('cases', caseId);
  if (!setHash(location, hash)) {
    showDetail(caseId).catch((err) => {
      casesCtx.detailPane.innerHTML = emptyState({ reason: 'error', title: 'Could not load this case', body: err.message });
    });
  }
}

export function goList() {
  const hash = hashFor('cases');
  if (!setHash(location, hash)) showList().catch(() => {});
}
