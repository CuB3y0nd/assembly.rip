import type { UserConfig } from '~/types'

export const userConfig: Partial<UserConfig> = {
  // Override the default config here
  site: {
    title: '活版印字',
    subtitle: '一片没有知识的荒原',
    author: 'CuB3y0nd',
    description: '一片没有知识的荒原',
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
      // {
      //   name: 'twitter',
      //   href: 'https://x.com/CuB3y0nd',
      // },
      // {
      //   name: 'mastodon',
      //   href: 'https://github.com/moeyua/astro-theme-typography',
      // },
    ],
    navLinks: [
      {
        name: 'Posts',
        href: '/',
      },
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
    ],
    categoryMap: [{ name: '胡适', path: 'hu-shi' }],
    footer: [
      '© %year <a target="_blank" href="%website">%author</a>',
      'Licensed under <a target="_blank" href="https://creativecommons.org/licenses/by-nc-sa/4.0/">4.0 CC-BY-NC-SA</a>'
    ],
  },
  appearance: {
    theme: 'light',
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
}
