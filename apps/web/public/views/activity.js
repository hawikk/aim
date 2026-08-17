/* Activity view shim — activity.js owns rendering; loader is a no-op so refresh() does not error. */
// The Activity trail (AIM-144) is a static tab (in #tabs / VALID_VIEWS), but
// activity.js owns fetching and rendering it (it watches the section for the
// .active class). This loader just resolves so refresh() doesn't throw a
// missing-loader error and prepend an error banner over the populated trail.
export const loadActivity = async () => {};
