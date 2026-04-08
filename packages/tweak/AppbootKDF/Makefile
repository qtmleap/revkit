TARGET := iphone:clang:16.5:15.0
INSTALL_TARGET_PROCESSES = Argo
ARCHS = arm64
THEOS_PACKAGE_SCHEME = rootless

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = AppbootKDF

AppbootKDF_FILES = $(shell find Sources/AppbootKDF -name '*.swift') $(shell find Sources/AppbootKDFC -name '*.m' -o -name '*.c' -o -name '*.mm' -o -name '*.cpp')
AppbootKDF_SWIFTFLAGS = -ISources/AppbootKDFC/include
AppbootKDF_CFLAGS = -fobjc-arc -ISources/AppbootKDFC/include -Wno-unused-function
AppbootKDF_FRAMEWORKS = Foundation
AppbootKDF_LDFLAGS = -lsubstrate

include $(THEOS_MAKE_PATH)/tweak.mk

after-install::
	install.exec "chmod 755 /var/jb/Library/MobileSubstrate/DynamicLibraries/AppbootKDF.dylib"
