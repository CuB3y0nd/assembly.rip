import mdx from '@astrojs/mdx'
import sitemap from '@astrojs/sitemap'
import swup from '@swup/astro'
import { defineConfig } from 'astro/config'
import robotsTxt from 'astro-robots-txt'
import UnoCSS from 'unocss/astro'
import { themeConfig } from './src/.config'
import { remarkAlert } from 'remark-github-blockquote-alert'

// https://astro.build/config
export default defineConfig({
  site: themeConfig.site.website,
  prefetch: true,
  base: '/',
  markdown: {
    remarkPlugins: [
      remarkAlert,
    ],
    rehypePlugins: [],
    shikiConfig: {
      theme: 'catppuccin-mocha',
      wrap: true,
    },
  },
  integrations: [
    UnoCSS({ injectReset: true }),
    mdx({
      recmaPlugins: [
        remarkAlert
      ],
      rehypePlugins: [],
      shikiConfig: {
        theme: 'catppuccin-mocha',
        wrap: true,
      },
    }),
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
