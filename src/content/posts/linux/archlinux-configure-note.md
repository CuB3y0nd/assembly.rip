---
title: "Arch Linux + Bspwm 配置小记"
published: 2023-07-29
description: "Arch Linux 安装小记"
image: "https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.7lkaiqpxos.avif"
tags: ["Linux", "Notes"]
category: "Notes"
draft: false
---

# 首先 flex 一下成品图

![](https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.32i9fr99d9.avif)

![](https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.175on4wtrm.avif)

![](https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.491kocy5ys.avif)

![](https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.5q7pq42api.avif)

_PS: 上面的成品图已经是远古时期的了，最新效果请看我的项目 [1llusion](https://github.com/CuB3y0nd/1llusion)._

# 分区方案规划

首先确定你要给 `Arch Linux` 划分多少内存。因为我电脑里是一块 1TB 的硬盘，所以我分了 512GB 给它，剩下的都留着给 Windows 用。

一个比较通用的方案是分以下三个区：

- EFI 分区：/efi 800MB
- 根分区：/ 100GB
- 用户主目录：/home 剩余全部

我设想的 Linux 分区方案如下：

- 4GB EFI
- 200GB root
- 300GB home
- 8GB swap

`swap` 分区虽然不一定用得上，但是个人建议分一下。一般设置为 `RAM` 的一半。不想给那么多的也可以直接给 2GB。

因为某些原因，我给 `EFI 分区` 4GB，实际上这个分区使用 800MB 即可。

# 确认 EFI 分区 大小

首先要确认 Windows 的 `EFI 分区` 大小是多少。如果你是 Win 10/Win 11 用户，按 `Win + X` 打开 **磁盘管理器**，在 **磁盘 0** 那块找到括号里写 **EFI 系统分区** 的那部分分区大小，记录下来，后面要用到。我这里是 100MB。

# 确认分区表类型

本篇文章仅针对使用 **GPT 分区表** 的用户，如果你是 MBR 的话部分安装指令需要修改，不能照抄。这里提供两种确认方式：

## 方法一

在 **磁盘管理器** 中，右键 **磁盘 0** 选择 **属性** 点击 **卷**，查看 **磁盘分区形式** 是否为 `GPT 分区表`。

## 方法二

部分用户右键 **磁盘 0** 可能会发现属性按钮是灰色的，无法点击，这里提供一种命令行的解决方案：「`Win + R` 输入 `diskpart` 回车，在打开的命令行窗口中输入 `list disk` 指令」，输出结果如下：

![](https://jsd.cdn.zzko.cn/gh/CuB3y0nd/picx-images-hosting@master/.6bhdcf4j00.avif)

如果看到 **磁盘 0** 的 **GPT 列表** 标注了一个 **\***，说明你符合我们的安装要求，可以进行下一步操作了。

# 划分空间

打开 **磁盘管理器**，右键 `C盘` 的主空间选择 **压缩卷** 在 **输入压缩空间量** 中输入你想给 Linux 划分的内存大小，单位 _MB（1GB = 1024MB）_ 比如我这里分出去 _512GB_，也就是 _524,288 MB_ 压缩完会看到一个黑色的未分配空间，这时候我们进入下一步操作，**不要右键新建简单卷！**

# 关闭快速启动并关闭休眠

为了双系统的安全性着想，需要关闭 Windows 的 `快速启动` 并关闭 `休眠` 选项至于为什么要关闭这两个选项见 [Dual boot with Windows](https://wiki.archlinux.org/title/Dual_boot_with_Windows)。

通过 [Dism++](https://dism.cf/) 软件可以轻易的关闭这两个选项：

在 `Dism++` -> `控制面板：系统优化` -> `其它` 即可找到这两个选项并关闭。

**Windows 更新可能会自动开启这两个选项，因此每次重大更新后都应该检查一下这两个选项的状态。**

# 准备安装盘

准备一个至少 `8GB` 大小的 U 盘，里面重要数据可以先备份一下，后面要格式化。

首先下载 [Rufus 烧录工具](https://rufus.ie/) 和 [Arch Linux 镜像文件](https://archlinux.org/download/)，镜像下载完后可以使用以下指令验证文件的完整性：

```bash
certutil -hashfile <filename> SHA256
```

然后复制输出的哈希值，去 Arch Linux 官网给出的 `sha256sum` 中核对有没有问题。如果匹配则说明文件没有问题。

打开下载好的 `Rufus` 工具，选择你的安装介质和刚才下载的镜像，其它参数默认，然后烧录。

烧录完成后不用拔出安装介质，直接重启电脑，进入 `BIOS 模式`，选择从你的 U 盘 启动，启动项一般包含 `UEFI` 字眼。

如果你不知道如何进入 `BIOS`，请自行百度。例：华硕进入 BIOS 按键。

如果发现无法从 U 盘 启动，提示需要关闭 `Secure Boot` 的，请参考下文的方式关闭它。

# 关闭 Secure Boot

因为从外部介质启动系统会被 `Secure Boot` ban，所以这里需要先去 `BIOS` 中禁用 `Secure Boot` 选项。

这个选项一般在 `BIOS` 的 `Advanced Settings` 的 `Security Settings` 选项中。将 `Enable` 改为 `Disable`。

关闭后请按照上面的说明再次进入 U 盘 启动，在打开的选择界面中选择第一项进行系统的安装。

# Arch Linux 系统安装

## 调大显示字体

```bash
setfont ter-132b
```

## 确认是否为 UEFI

```bash
ls /sys/firmware/efi/efivars
```

如果用上面这条指令后输出了一堆东西则说明处于 `UEFI`，如果没有，那你可能只能用 `Legacy` 启动了。

## 禁用并停止自动匹配最快源服务

`reflector` 会为你选择速度合适的镜像源，但其结果并不准确，同时会清空配置文件中的内容，对于新人来讲并不适用，我们首先对其进行禁用。

```bash
systemctl disable reflector.service
systemctl stop reflector.service
```

## 设置时区

```bash
timedatectl set-timezone Asia/Shanghai
timedatectl status
```

## 分区

先用 `lsblk` 指令查看你的硬盘是哪块，然后通过 `cfdisk` 指令进行分区。

这是我的分区方案：

- 4G - EFI
- 200G - root
- 300G - home
- 8G - swap

`cfdisk` 分好区之后记得要 **设置类型**。

**`nvme0n1` 是我的硬盘 ID，记得替换为你自己的。**

```bash
lsblk
cfdisk /dev/nvme0n1
```

## 格式化分区

- EFI 分区 格式化为 fat
- root 分区 格式化为 ext4
- home 分区 格式化为 ext4
- 创建并启用 swap 分区

```bash
lsblk
mkfs.fat -F 32 /dev/nvme0n1p5
mkfs.ext4 /dev/nvme0n1p6
mkfs.ext4 /dev/nvme0n1p7
fallocate -l 8192M /mnt/swapfile
chmod 600 /mnt/swapfile
mkswap -L swap /mnt/swapfile
swapon /mnt/swapfile
lsblk
```

## 挂载分区

**挂载顺序：一定要先挂载 根分区，再挂载 EFI 分区，最后其它分区。**

```bash
mount /dev/nvme0n1p6 /mnt
mkdir /mnt/efi
mount /dev/nvme0n1p5 /mnt/efi
mkdir /mnt/home
mount /dev/nvme0n1p7 /mnt/home
lsblk
```

## 换源

```bash
cp /etc/pacman.d/mirrorlist /etc/pacman.d/mirrorlist.bak
cat /dev/null > /etc/pacman.d/mirrorlist
vim /etc/pacman.d/mirrorlist

添加如下源：
Server = https://mirrors.ustc.edu.cn/archlinux/$repo/os/$arch
Server = https://mirrors.tuna.tsinghua.edu.cn/archlinux/$repo/os/$arch
保存并退出

pacman -Sy
```

## 安装基础软件包

所有 Arch Linux 必装：

- `base`
- `base-devel`
- `linux-zen`
- `linux-zen-headers`
- `linux-firmware`

> [!TIP]
> 上面根据个人喜好选择内核，我使用了 `zen`。

根据自己的 CPU 决定用哪个微码：`amd-ucode` / `intel-ucode`

使用 X11 服务显示桌面：`xorg-xinit` `xorg-server`

fcitx5 输入法（不需要中文输入的可以不装）：

- `fcitx5`
- `fcitx5-chinese-addons`
- `fcitx5-configtool`
- `fcitx5-gtk`
- `fcitx5-material-color`
- `fcitx5-pinyin-zhwiki`

这几个常用工具应该没人不需要吧：

- `sudo`
- `neofetch`
- `vim`
- `neovim`
- `git`
- `wget`
- `proxychains`
- `btop`
- `bash-completion`

网络方面（没这些就别想用 `wlan` 了）：

- `iwd`
- `networkmanager`

音频输出：

- `pipewire`
- `pipewire-pulse`
- `pipewire-alsa`
- `pipewire-jack`

杂项（必装）：`e2fsprogs` `ntfs-3g`

字体（不装的话所有中文都是乱码）：

- `adobe-source-han-serif-cn-fonts`
- `wqy-zenhei`
- `noto-fonts-cjk`
- `noto-fonts-emoji`
- `noto-fonts-extra`

蓝牙（可选）：`bluez`

下面是一些我个人常用的软件：

```
bat dust duf procs btop exa ripgrep fd fzf httpie hyperfine
bleachbit gimp gcolor3 simplescreenrecorder
thunar thunar-archive-plugin tumbler xarchiver
ueberzug viewnior zathura zathura-pdf-poppler
pacman-contrib copyq yt-dlp transmission-gtk
papirus-icon-theme ttf-joypixels terminus-font grsync
ffmpeg ffmpegthumbnailer aom libde265 x265 x264 libmpeg2 xvidcore libtheora libvpx sdl
jasper openjpeg2 libwebp webp-pixbuf-loader
unarchiver lha lrzip lzip p7zip lbzip2 arj lzop cpio unrar unzip zip unarj xdg-utils
xorg-server xorg-xinput xorg-xsetroot zramswap qogir-icon-theme
```

```bash
pacstrap -i /mnt base base-devel linux-zen linux-zen-headers linux-firmware amd-ucode xorg-xinit xorg-server fcitx5 fcitx5-chinese-addons fcitx5-configtool fcitx5-gtk fcitx5-material-color fcitx5-pinyin-zhwiki sudo neofetch neovim git wget proxychains btop iwd networkmanager alsa-utils e2fsprogs ntfs-3g bash-completion pipewire pipewire-pulse pipewire-alsa pipewire-jack adobe-source-han-serif-cn-fonts wqy-zenhei noto-fonts-cjk noto-fonts-emoji noto-fonts-extra bluez
```

## 生成 fstab

```bash
genfstab -U /mnt >>/mnt/etc/fstab
cat /mnt/etc/fstab
```

## 挂载 /mnt 分区

```bash
arch-chroot /mnt
```

## 设置用户和密码

```bash
# 此处分别设置：root 用户密码、添加自己日常使用的用户、设置用户权限组（注意逗号后面没空格）、为自己的账户设置密码、设置 wheel 组可以执行 sudo
passwd
useradd -m cub3y0nd
passwd cub3y0nd
usermod -aG wheel,storage,power -s /usr/bin/zsh cub3y0nd
sudo nvim /etc/sudoers

取消注释第 89 行：%wheel ALL=(ALL:ALL) ALL
```

_如果你不会使用 vim，最好自己查询一下基础操作。_

## 设置系统语言

```bash
nvim /etc/locale.gen

取消注释第 171 行：en_US.UTF-8 UTF-8

locale-gen
echo 'LANG=en_US.UTF-8' > /etc/locale.conf
export LANG=en_US.UTF-8
```

## 设置主机名和 hosts（我的主机名是 ASHES）

```bash
echo ASHES > /etc/hostname
nvim /etc/hosts

添加以下内容：
127.0.0.1        localhost
::1              localhost
127.0.0.1        ASHES.localdomain        localhost
```

## 设置时区并同步

```bash
ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
hwclock --systohc
```

## 双系统引导设置

```bash
pacman -S grub efibootmgr os-prober ntfs-3g dosfstools mtools
nvim /etc/default/grub

将 `GRUB_CMDLINE_LINUX_DEFAULT` 的所有内容改为 GRUB_CMDLINE_LINUX_DEFAULT="loglevel=5 nowatchdog"

loglevel 改为 5 是为了后续如果出现系统错误，方便排错加入 nowatchdog 参数，可以显著提高开关机速度

取消注释第 63 行：`GRUB_DISABLE_OS_PROBER=false`
```

## 安装 UEFI

**这一步使用 `MBR/Legacy Boot` 的同学需要修改该指令，具体怎么改可以自己上网查询。**

```bash
grub-install --target=x86_64-efi --efi-directory=/efi --bootloader-id=Arch --recheck
```

## 生成 grub 配置

```bash
grub-mkconfig -o /boot/grub/grub.cfg
```

## 设置网络服务开机自启

```bash
systemctl enable NetworkManager.service
```

## 结束安装，取消所有挂载点并重启

```bash
exit
umount -lR /mnt
reboot
```

**重启指令执行后就可以拔掉安装介质了。其实在 `archiso` 启动完毕之后就可以拔掉安装介质了（copy2ram）。**

重启后的选项卡列表里面可以看到有关 `Arch Linux` 的启动选项。确认一下是否存在 `Windows` 的启动选项，如果不存在的话，先进入 `Arch Linux`，然后使用以下命令添加 `Windows 启动项`。

**`mount` 中的 `/dev/nvme0n1p1` 是我的 `Windows EFI` 扇区名称，记得替换为你自己的 `EFI 扇区`。**

使用 `MBR/Legacy Boot` 的同学，下面的 `mkdir` 指令也需要修改，不能照抄。

```bash
mkdir -p /boot/EFI/Windows
lsblk
mount /dev/nvme0n1p1 /boot/EFI/Windows
```

# Bspwm

接下来就可以使用我编写的自动化脚本配置一些常用环境了。

我的 `dotfiles` 仓库地址：[1llusion](https://github.com/CuB3y0nd/1llusion)

**确保 fcitx 在 wm（windows manager）环境中启动，并启动 bspwm。**

```bash
nvim /etc/environment

添加以下行：
export GTK_IM_MODULE=fcitx
export QI_IM_MODULE=fcitx
export XMODIFIERS=@im=fcitx
SDL_IM_MODULE=fcitx
export GLFW_IM_MODULE=ibus

cp /etc/X11/xinit/xinitrc ~/.xinitrc
nvim ~/.xinitrc

注释以下行：
twm &
xclock -geometry 50x50-1+1 &
xterm -geometry 80x50+494+51 &
xterm -geometry 80x20+494-0 &
exec xterm -geometry 80x66+8+0 -name login

添加以下行：
fcitx5 &
exec bspwm
```

## 下载脚本

```bash
cd
curl https://raw.githubusercontent.com/CuB3y0nd/1llusion/master/install -o $HOME/install
```

## 授予执行权限

```bash
chmod +x install
```

## 运行脚本

```bash
./install
```

**_请不要使用 root 权限运行该脚本！_**

脚本执行结束后重启，使用 `startx` 指令即可进入 `bspwm`。

# AMD + NVIDIA 双显卡驱动安装

## 基础包安装

```bash
sudo pacman -S xf86-video-amdgpu
sudo pacman -S nvidia-dkms nvidia-settings nvidia-prime

# glmark2 是开源性能测试工具，可选
sudo pacman -S glmark2

yay -S optimus-manager optimus-manager-qt --noconfirm
```

## 配置 optimus-manager

```bash
cp /usr/share/optimus-manager.conf /etc/optimus-manager/optimus-manager.conf

sudo -E nvim /etc/optimus-manager/optimus-manager.conf

将 `pci_power_control` 改为 `yes`

在 `[amd]` 下，将 `driver` 改为 `amdgpu`
```

## 防止内核冲突

```bash
sudo -E nvim /etc/mkinitcpio.conf

把 `kms` 从 `HOOKS` 里面移除

sudo mkinitcpio -p linux-zen
```

## 切换教程

```bash
sudo -E nvim ~/.xinitrc

添加 `/usr/bin/prime-offload`
```

使用 `optimus-manager --print-mode` 可以查看当前使用的显卡。

使用 `optimus-manager --switch nvidia` 可以切换到 `nvidia` 显卡。

切换显卡前需要先执行 `prime-offload`，切换显卡重新登陆后需要执行 `sudo prime-switch`。

可以允许 `wheel` 身份组以管理员权限执行 `prime-switch` 不用输入密码：

```bash
sudo -E nvim /etc/sudoers

%wheel ALL=(ALL:ALL) NOPASSWD:/usr/bin/prime-switch
```
