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
	subtitle: "塵海起伏，心燈長明",
	lang: "en",
	themeColor: {
		hue: 250,
		fixed: false,
	},
	banner: {
		enable: true,
		src: "https://cdn.jsdmirror.com/gh/CuB3y0nd/picx-images-hosting@master/.1lc58276dr.avif",
		position: "center",
		credit: {
			enable: true,
			text: "落日歸山海，與你話清風。",
			url: "https://www.pixiv.net/en/artworks/110056120",
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
		LinkPreset.Archive,
		LinkPreset.Friends,
		LinkPreset.About,
		LinkPreset.Collections,
		{
			name: "Memos",
			url: "https://memos.cubeyond.net/",
			external: true,
		},
	],
};

export const profileConfig: ProfileConfig = {
	avatar: "assets/images/avatar.jpg",
	name: "CuB3y0nd",
	bio: "心之所向，一苇以航。",
	links: [
		{
			name: "Home",
			icon: "material-symbols:verified-outline-rounded",
			url: "https://www.cubeyond.net",
		},
		{
			name: "Memos",
			icon: "mingcute:moment-line",
			url: "https://memos.cubeyond.net",
		},
		{
			name: "GitHub",
			// Visit https://icones.js.org/ for icon codes
			// You will need to install the corresponding icon set if it's not already included
			// `pnpm add @iconify-json/<icon-set-name>`
			icon: "tabler:brand-github",
			url: "https://github.com/CuB3y0nd",
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
