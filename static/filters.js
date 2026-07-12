/* Reusable, declarative client-side filtering / search / sort.
 *
 * Filter group (works for table rows OR card lists):
 *   <div data-filter-group data-items="#appTable tbody tr">
 *     <input data-role="search" placeholder="Search...">
 *     <select data-role="filter" data-attr="severity"> ... </select>
 *     <div class="chips"><span class="chip" data-role="chip" data-attr="risktype" data-value="VULNERABLE_DEPENDENCY">...</span></div>
 *     <button data-role="reset">Reset</button>
 *     <span data-role="count"></span>
 *   </div>
 * Items carry data-* attributes (data-severity, data-risktype, ...) matched case-insensitively.
 * An item is shown when the search text matches AND every active select/chip attribute matches.
 *
 * Sortable table: <table data-sortable> with <th data-sort="num|text">.
 * Cells may carry data-val to sort on a value different from their text.
 */
(function () {
  function initGroup(group) {
    const items = () => Array.from(document.querySelectorAll(group.dataset.items));
    const search = group.querySelector('[data-role=search]');
    const selects = Array.from(group.querySelectorAll('select[data-role=filter]'));
    const chips = Array.from(group.querySelectorAll('[data-role=chip]'));
    const countEl = group.querySelector('[data-role=count]');
    const emptyRow = group.dataset.empty ? document.querySelector(group.dataset.empty) : null;

    // chips are multi-select per attribute: active set keyed by attr
    const active = {};
    chips.forEach(c => c.addEventListener('click', () => {
      const a = c.dataset.attr;
      active[a] = active[a] || new Set();
      if (active[a].has(c.dataset.value)) { active[a].delete(c.dataset.value); c.classList.remove('on'); }
      else { active[a].add(c.dataset.value); c.classList.add('on'); }
      apply();
    }));

    function apply() {
      const q = (search && search.value || '').toLowerCase().trim();
      const all = items();
      let shown = 0;
      all.forEach(it => {
        let ok = true;
        if (q && !it.textContent.toLowerCase().includes(q)) ok = false;
        if (ok) for (const s of selects) {
          if (s.value && (it.getAttribute('data-' + s.dataset.attr) || '').toLowerCase() !== s.value.toLowerCase()) { ok = false; break; }
        }
        if (ok) for (const a in active) {
          if (active[a].size && !active[a].has(it.getAttribute('data-' + a))) { ok = false; break; }
        }
        it.style.display = ok ? '' : 'none';
        if (ok) shown++;
      });
      if (countEl) countEl.textContent = shown + ' of ' + all.length;
      if (emptyRow) emptyRow.style.display = shown ? 'none' : '';
    }

    if (search) search.addEventListener('input', apply);
    selects.forEach(s => s.addEventListener('change', apply));
    group.querySelectorAll('[data-role=reset]').forEach(b => b.addEventListener('click', () => {
      if (search) search.value = '';
      selects.forEach(s => s.value = '');
      chips.forEach(c => c.classList.remove('on'));
      for (const a in active) active[a].clear();
      apply();
    }));
    apply();
    group._apply = apply;
  }

  function initSort(tbl) {
    const heads = Array.from(tbl.querySelectorAll('th[data-sort]'));
    heads.forEach(th => th.addEventListener('click', () => {
      const tbody = tbl.tBodies[0];
      const ci = Array.from(th.parentNode.children).indexOf(th);
      const type = th.dataset.sort;
      const asc = !th.classList.contains('asc');
      heads.forEach(h => h.classList.remove('asc', 'desc'));
      th.classList.add(asc ? 'asc' : 'desc');
      const rows = Array.from(tbody.rows).filter(r => !r.classList.contains('empty-row'));
      rows.sort((a, b) => {
        const av = a.cells[ci], bv = b.cells[ci];
        let x = av && (av.dataset.val ?? av.textContent.trim()) || '';
        let y = bv && (bv.dataset.val ?? bv.textContent.trim()) || '';
        if (type === 'num') { x = parseFloat(x) || 0; y = parseFloat(y) || 0; return asc ? x - y : y - x; }
        return asc ? String(x).localeCompare(String(y)) : String(y).localeCompare(String(x));
      });
      rows.forEach(r => tbody.appendChild(r));
    }));
  }

  document.addEventListener('DOMContentLoaded', function () {
    document.querySelectorAll('[data-filter-group]').forEach(initGroup);
    document.querySelectorAll('table[data-sortable]').forEach(initSort);
  });
})();
