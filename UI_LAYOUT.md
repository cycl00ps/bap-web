# UI Layout Contract

The BAP Web UI is intentionally simple server-rendered HTML with shared CSS. New pages should follow these rules so management panels and tables stay usable across common desktop, laptop, tablet, and mobile widths.

## Page Structure

- Use `.grid` or `.split` for two-column management pages.
- Put the primary content in the left column and forms/tools in a right `aside.panel`.
- Do not set fixed pixel widths on page content beyond the shared grid/sidebar classes.
- Right panels must be allowed to stack below main content at smaller widths.

## Tables

- Every normal data table must be wrapped in:

```html
<div class="table-wrap">
  <table>...</table>
</div>
```

- Long values such as IDs, paths, checksums, source URLs, and errors should be placed in elements that can wrap, such as `code`, `.hint`, or `.error-cell`.
- Do not put large forms, textareas, or multi-field editors inside table action cells.
- Table action cells should contain short commands only. Move bulky edits into a separate settings section, detail page, or dedicated form panel.

## Forms And Actions

- Use `.stack` for vertical forms.
- Use `.inline-form` or `.compact-form` only when controls can wrap cleanly.
- Buttons in table rows should be short and stable, such as `Start`, `Stop`, `Test`, `Open`, or `Delete`.

## Responsive Expectations

- At wide desktop widths, two-column pages may render side by side.
- At laptop/tablet widths, grids stack before content overlaps.
- At mobile widths, forms are one column and wide tables scroll inside `.table-wrap`.
- The document body should not require horizontal scrolling during normal use.
