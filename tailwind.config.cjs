/** @type {import('tailwindcss').Config} */
const defaultTheme = require("tailwindcss/defaultTheme")
module.exports = {
  theme: {
    extend: {
      fontFamily: {
        sans: [
          "LXGW Bright Light",
          "PingFang SC",
          "Hiragino Sans GB",
          "Microsoft YaHei",
          "Noto Sans CJK SC",
          "Source Han Sans SC",
          ...defaultTheme.fontFamily.sans,
        ],
      },
    },
  },
}
