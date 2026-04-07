TARGET := iphone:clang:16.5:15.0
INSTALL_TARGET_PROCESSES = Argo
ARCHS = arm64
THEOS_PACKAGE_SCHEME = rootless

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = NetflixSSLBypass

NetflixSSLBypass_FILES = Sources/NetflixSSLBypass/Tweak.x.swift Sources/NetflixSSLBypass/ctor.c
NetflixSSLBypass_SWIFT_FLAGS = -ISources/NetflixSSLBypass
NetflixSSLBypass_FRAMEWORKS = Foundation
NetflixSSLBypass_LDFLAGS = -lsubstrate

include $(THEOS_MAKE_PATH)/tweak.mk
