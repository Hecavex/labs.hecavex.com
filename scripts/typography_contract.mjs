import assert from 'node:assert/strict';

// Match Research's role metrics, not one blanket size. Operational identifiers
// and compact evidence headings retain their semantic sizes and monospace face.
const roles = [
  ['body', 'Inter', 400, 1.65, -.006, 16],
  ['h1', 'Space Grotesk', 600, 1.08, -.04],
  ['h2', 'Space Grotesk', 600, 1.1, -.035],
  ['h3', 'Space Grotesk', 600, 1.2, -.035],
  ['.portfolio-navigation a, .product-navigation a, .mobile-navigation-panel a:not(.mobile-header-utility)', 'Inter', 600, 'normal', 0, 12],
  ['.brand-copy small, .product-identity span', 'Inter', 500, 'normal', 0, 12],
  ['.header-search input, .mobile-header-search input, .header-utility, .mobile-header-utility, .mobile-navigation summary', 'Inter', 600, 'normal', 0, 12],
  ['.brand-hero .lead, .page-head .lead, .evidence-hero .lead', 'Inter', 400, 1.45, -.006, 'lead'],
  ['main .eyebrow', 'Inter', 600, 1.5, .02, 12],
  ['.button, .row-action, .mapping-dialog-head .dialog-close', 'Inter', 600, 1.5, 0, 14],
];

export async function assertTypography(page, context) {
  const samples = await page.evaluate(definitions => definitions.flatMap(([selector, ...expected]) =>
    [...document.querySelectorAll(selector)].map(element => {
      const style = getComputedStyle(element);
      return {
        selector, expected, viewport: innerWidth,
        family: style.fontFamily.split(',')[0].replaceAll('"', '').trim(),
        size: parseFloat(style.fontSize), weight: Number(style.fontWeight),
        leading: style.lineHeight === 'normal' ? 'normal' : parseFloat(style.lineHeight),
        tracking: style.letterSpacing === 'normal' ? 0 : parseFloat(style.letterSpacing),
      };
    })), roles);
  for (const sample of samples) {
    const [family, weight, leading, tracking, size] = sample.expected;
    const label = `${sample.selector}: ${context}`;
    assert.equal(sample.family, family, `type family: ${label}`);
    assert.equal(sample.weight, weight, `type weight: ${label}`);
    if (leading === 'normal') assert.equal(sample.leading, 'normal', `type leading: ${label}`);
    else assert(Math.abs(sample.leading - sample.size * leading) < .03, `type leading: ${label}`);
    assert(Math.abs(sample.tracking - sample.size * tracking) < .03, `type tracking: ${label}`);
    const expectedSize = size === 'lead' ? Math.min(20, Math.max(17.6, sample.viewport * .016)) : size;
    if (expectedSize !== undefined) assert(Math.abs(sample.size - expectedSize) < .03, `type size: ${label}`);
  }
}
