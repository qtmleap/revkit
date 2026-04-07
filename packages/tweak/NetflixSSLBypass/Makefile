TARGET := iphone:clang:16.5:15.0
INSTALL_TARGET_PROCESSES = Argo
ARCHS = arm64
THEOS_PACKAGE_SCHEME = rootless

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = NetflixSSLBypass

NetflixSSLBypass_FILES = $(shell find Sources/NetflixSSLBypass -name '*.swift') $(shell find Sources/NetflixSSLBypassC -name '*.m' -o -name '*.c' -o -name '*.mm' -o -name '*.cpp')
NetflixSSLBypass_SWIFTFLAGS = -ISources/NetflixSSLBypassC/include
NetflixSSLBypass_CFLAGS = -fobjc-arc -ISources/NetflixSSLBypassC/include
NetflixSSLBypass_FRAMEWORKS = UIKit

include $(THEOS_MAKE_PATH)/tweak.mk

after-install::
	install.exec "chmod 755 /var/jb/Library/MobileSubstrate/DynamicLibraries/NetflixSSLBypass.dylib"
