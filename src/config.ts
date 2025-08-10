import type {
	ExpressiveCodeConfig,
	LicenseConfig,
	NavBarConfig,
	ProfileConfig,
	SiteConfig,
} from "./types/config";
import { LinkPreset } from "./types/config";

export const siteConfig: SiteConfig = {
	title: "熵餘記事",
	subtitle: "Per aspera ad astra",
	lang: "en",
	themeColor: {
		hue: 250,
		fixed: false,
	},
	banner: {
		enable: true,
		src: "https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.6m47vyn1pe.avif",
		position: "center",
		credit: {
			enable: true,
			text: "蓝色风暴——Blue",
			url: "https://www.pixiv.net/en/artworks/119807651",
		},
	},
	toc: {
		enable: true,
		depth: 3,
	},
	favicon: [
		{
			src: "/favicon/favicon.svg",
			// theme: 'light',
			// sizes: '32x32',
		},
	],
};

export const navBarConfig: NavBarConfig = {
	links: [
		LinkPreset.Home,
		LinkPreset.Archive,
		LinkPreset.About,
		LinkPreset.Friends,
		{
			name: "GitHub",
			url: "https://github.com/CuB3y0nd",
			external: true,
		},
	],
};

export const profileConfig: ProfileConfig = {
	avatar: "assets/images/avatar.png",
	name: "CuB3y0nd",
	bio: "心之所向，一苇以航。",
	links: [
		{
			name: "GitHub",
			// Visit https://icones.js.org/ for icon codes
			// You will need to install the corresponding icon set if it's not already included
			// `pnpm add @iconify-json/<icon-set-name>`
			icon: "tabler:brand-github",
			url: "https://github.com/CuB3y0nd",
		},
		{
			name: "Memos",
			icon: "mingcute:moment-line",
			url: "https://memos.cubeyond.net",
		},
		{
			name: "RSS",
			icon: "material-symbols:rss-feed-rounded",
			url: "/rss.xml",
		},
	],
};

export const licenseConfig: LicenseConfig = {
	enable: true,
	name: "CC BY-NC-SA 4.0",
	url: "https://creativecommons.org/licenses/by-nc-sa/4.0/",
};

export const expressiveCodeConfig: ExpressiveCodeConfig = {
	// Note: Some styles (such as background color) are being overridden, see the astro.config.mjs file.
	themes: ["catppuccin-latte", "catppuccin-macchiato"],
};
