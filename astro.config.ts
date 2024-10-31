import mdx from '@astrojs/mdx'
import sitemap from '@astrojs/sitemap'
import swup from '@swup/astro'
import { defineConfig } from 'astro/config'
import robotsTxt from 'astro-robots-txt'
import remarkToc from 'remark-toc'
import remarkCollapse from 'remark-collapse'
import { remarkAlert } from 'remark-github-blockquote-alert'
import remarkMath from 'remark-math'
import { rehypeHeadingIds } from '@astrojs/markdown-remark'
import rehypeAutolinkHeadings from 'rehype-autolink-headings'
import rehypeKatex from 'rehype-katex'
import UnoCSS from 'unocss/astro'
import { themeConfig } from './src/.config'

// https://astro.build/config
export default defineConfig({
  site: themeConfig.site.website,
  prefetch: true,
  base: '/',
  markdown: {
    remarkPlugins: [
      remarkToc,
      [
        remarkCollapse,
        {
          test: "Table of contents",
        },
      ],
      remarkAlert,
      remarkMath,
    ],
    rehypePlugins: [
      rehypeHeadingIds,
      [
        rehypeAutolinkHeadings,
        {
          behavior: 'wrap',
        },
      ],
      rehypeKatex,
    ],
    shikiConfig: {
      theme: 'catppuccin-mocha',
      wrap: true,
    },
  },
  integrations: [
    UnoCSS({ injectReset: true }),
    mdx({}),
    robotsTxt(),
    sitemap(),
    swup({
      theme: false,
      animationClass: 'transition-swup-',
      cache: true,
      preload: true,
      accessibility: true,
      smoothScrolling: true,
      updateHead: true,
      updateBodyClass: true,
    }),
  ],
})
