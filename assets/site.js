document.querySelectorAll('[data-year]').forEach((el) => { el.textContent = new Date().getFullYear(); });

const filters = [...document.querySelectorAll('[data-filter]')];
const records = [...document.querySelectorAll('[data-record]')];
function filterRecords() {
  if (!records.length) return;
  const state = Object.fromEntries(filters.map((el) => [el.dataset.filter, el.value.toLowerCase()]));
  records.forEach((record) => {
    const haystack = record.textContent.toLowerCase();
    const searchable = !state.search || haystack.includes(state.search);
    const matching = ['country', 'type', 'year'].every((key) => !state[key] || record.dataset[key] === state[key]);
    record.hidden = !(searchable && matching);
  });
}
filters.forEach((el) => el.addEventListener(el.tagName === 'INPUT' ? 'input' : 'change', filterRecords));
