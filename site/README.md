# The ocmf website

The landing page and documentation at <https://hupe1980.github.io/ocmf>, built
with [Zola](https://www.getzola.org/).

```console
$ zola --root site serve     # http://127.0.0.1:1111, live reload
$ zola --root site check     # dead links and broken internal references
$ zola --root site build     # writes site/public/
```

`.github/workflows/site.yml` runs `check` and `build` on every pull request and
deploys `main` to GitHub Pages.

## Layout

```
config.toml            base URL, SEO defaults, the numbers the site quotes
content/_index.md      the landing page
content/docs/*.md      one page per topic, ordered by `weight`
templates/             base, home, section, page, 404
templates/partials/    sidebar, table of contents, JSON-LD
sass/main.scss         the whole design system: tokens, layout, components
static/                favicon, Open Graph image, robots.txt, search
```

## Conventions

- **No web fonts and no render-blocking JavaScript.** A documentation page is
  about 5&nbsp;KB of gzipped HTML plus 4&nbsp;KB of CSS; search loads only when
  the box is focused, and nothing on the page depends on it.
- **Every page carries a `description`.** It becomes the meta description, the
  Open Graph description and the sidebar summary, so it should read as a
  sentence rather than a label.
- **Structured data matches the page.** `SoftwareSourceCode` on the home page,
  `TechArticle` plus `BreadcrumbList` on documentation pages, and `FAQPage` only
  where the front matter actually lists questions.
- **Numbers live in `config.toml`** under `[extra]`, so the landing page and the
  documentation cannot disagree about them.

## Editing

Add a page by dropping a Markdown file in `content/docs/` with front matter:

```toml
+++
title = "Sessions"
description = "One sentence. It is the meta description and the sidebar summary."
weight = 7
+++
```

`weight` orders the sidebar and the previous/next links. Internal links use
Zola's `@/` syntax — `[Verifying](@/docs/verifying.md)` — so `zola check` catches
a rename.
