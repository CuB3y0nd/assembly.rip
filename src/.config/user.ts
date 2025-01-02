import type { UserConfig } from '~/types'

export const userConfig: Partial<UserConfig> = {
  // Override the default config here
  site: {
    title: '熵餘記事',
    subtitle: 'Per aspera ad astra',
    author: 'CuB3y0nd',
    description: 'Per aspera ad astra',
    website: 'https://assembly.rip/',
    pageSize: 5,
    socialLinks: [
      {
        name: 'github',
        href: 'https://github.com/CuB3y0nd',
      },
      {
        name: 'rss',
        href: '/atom.xml',
      },
      {
        name: 'email',
        href: 'mailto:root@cubeyond.net',
      },
    ],
    navLinks: [
      {
        name: 'Archive',
        href: '/archive',
      },
      {
        name: 'Categories',
        href: '/categories',
      },
      {
        name: 'About',
        href: '/about',
      },
      {
        name: 'Links',
        href: '/friends',
      },
    ],
    footer: [
      '© %year <a target="_blank" href="%website">%author</a>',
      'Licensed under <a target="_blank" href="https://creativecommons.org/licenses/by-nc-sa/4.0/">4.0 CC-BY-NC-SA</a>'
    ],
  },
  appearance: {
    theme: 'system',
    locale: 'zh-cn',
    colorsLight: {
      primary: '#2e405b',
      background: '#ffffff',
    },
    colorsDark: {
      primary: '#FFFFFF',
      background: '#232222',
    },
    fonts: {
      header:
        '"HiraMinProN-W6","Source Han Serif CN","Source Han Serif SC","Source Han Serif TC",serif',
      ui: '"Source Sans Pro","Roboto","Helvetica","Helvetica Neue","Source Han Sans SC","Source Han Sans TC","PingFang SC","PingFang HK","PingFang TC",sans-serif',
    },
  },
  seo: {
    twitter: '@CuB3y0nd',
    meta: [],
    link: [],
  },
  rss: {
    fullText: true,
  },
  latex: {
    katex: true,
  },
  comment: {
    giscus: {
      repo: 'CuB3y0nd/comments',
      repoId: 'R_kgDOLLmM2g',
      category: 'Announcements',
      categoryId: 'DIC_kwDOLLmM2s4Ccz0I',
      mapping: 'pathname',
      strict: '0',
      reactionsEnabled: '1',
      emitMetadata: '1',
      inputPosition: 'top',
      theme: 'noborder_light',
      lang: 'zh-CN',
      loading: 'lazy',
    }
  },
}
