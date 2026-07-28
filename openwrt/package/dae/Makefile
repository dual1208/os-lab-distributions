# SPDX-License-Identifier: GPL-2.0-only
# Packaging pattern derived from ImmortalWrt and douglarek/dae-openwrt.
# dae itself is AGPL-3.0-only; see the source archive's LICENSE.

include $(TOPDIR)/rules.mk

PKG_NAME:=dae
PKG_VERSION:=2.0.0
PKG_RELEASE:=1

PKG_SOURCE:=dae-full-src.tar.xz
PKG_SOURCE_URL:=https://github.com/daeuniverse/dae/releases/download/v$(PKG_VERSION)
PKG_HASH:=51e5fe169a36c03503d74f3cb93a00a4547e41b5a8bd957599bfac0094639061
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

PKG_LICENSE:=AGPL-3.0-only
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=OS Lab <noreply@example.invalid>

PKG_BUILD_DEPENDS:=golang/host bpf-headers
PKG_BUILD_PARALLEL:=1
PKG_BUILD_FLAGS:=no-mips16

GO_PKG:=github.com/daeuniverse/dae
GO_PKG_EXCLUDES:=control/kern/tests trace
GO_PKG_LDFLAGS_X:= \
	$(GO_PKG)/cmd.Version=$(PKG_VERSION) \
	$(GO_PKG)/common/consts.MaxMatchSetLen_=1024

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/bpf.mk
include $(TOPDIR)/feeds/packages/lang/golang/golang-package.mk

define Package/dae
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Web Servers/Proxies
  TITLE:=High-performance eBPF transparent proxy
  URL:=https://github.com/daeuniverse/dae
  DEPENDS:=$(GO_ARCH_DEPENDS) $(BPF_DEPENDS) \
    +ca-bundle +kmod-sched-core +kmod-sched-bpf +kmod-veth \
    +v2ray-geoip +v2ray-geosite +@KERNEL_XDP_SOCKETS
endef

define Package/dae/description
 dae is an eBPF-based transparent proxy. This package is disabled by default
 and contains no proxy subscription, node, or credential configuration.
endef

define Package/dae/conffiles
/etc/config/dae
/etc/dae/config.dae
endef

DAE_CFLAGS:= \
	-O2 -Wall -Werror \
	-DMAX_MATCH_SET_LEN=1024 \
	-I$(BPF_HEADERS_DIR)/tools/lib \
	-I$(BPF_HEADERS_DIR)/arch/$(BPF_KARCH)/include/asm/mach-generic

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(TAR) --strip-components=1 -C $(PKG_BUILD_DIR) -xf $(DL_DIR)/$(PKG_SOURCE)
endef

define Build/Compile
	( \
		export \
		$(GO_GENERAL_BUILD_CONFIG_VARS) \
		$(GO_PKG_BUILD_CONFIG_VARS) \
		$(GO_PKG_BUILD_VARS) \
		BPF_CLANG="$(CLANG)" \
		BPF_STRIP_FLAG="-strip=$(LLVM_STRIP)" \
		BPF_CFLAGS="$(DAE_CFLAGS)" \
		BPF_TARGET="bpfel,bpfeb" \
		BPF_TRACE_TARGET="$(GO_ARCH)" ; \
		go generate $(PKG_BUILD_DIR)/control/control.go ; \
		$(call GoPackage/Build/Compile) ; \
	)
endef

define Package/dae/install
	$(call GoPackage/Package/Install/Bin,$(1))

	$(INSTALL_DIR) $(1)/etc/dae
	$(INSTALL_CONF) $(CURDIR)/files/config.dae $(1)/etc/dae/config.dae

	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) $(CURDIR)/files/dae.config $(1)/etc/config/dae

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(CURDIR)/files/dae.init $(1)/etc/init.d/dae
endef

$(eval $(call GoBinPackage,dae))
$(eval $(call BuildPackage,dae))

