TARGET := iphone:clang:16.5:15.0
INSTALL_TARGET_PROCESSES = Argo
ARCHS = arm64
THEOS_PACKAGE_SCHEME = rootless

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = NetflixEntityAuth

NetflixEntityAuth_FILES = $(shell find Sources/NetflixEntityAuth -name '*.swift') $(shell find Sources/NetflixEntityAuthC -name '*.m' -o -name '*.c' -o -name '*.mm' -o -name '*.cpp')
NetflixEntityAuth_SWIFTFLAGS = -ISources/NetflixEntityAuthC/include
NetflixEntityAuth_CFLAGS = -fobjc-arc -ISources/NetflixEntityAuthC/include -Wno-unused-function
NetflixEntityAuth_FRAMEWORKS = Foundation
NetflixEntityAuth_LDFLAGS = -lsubstrate

include $(THEOS_MAKE_PATH)/tweak.mk

after-install::
	install.exec "chmod 755 /var/jb/Library/MobileSubstrate/DynamicLibraries/NetflixEntityAuth.dylib"
