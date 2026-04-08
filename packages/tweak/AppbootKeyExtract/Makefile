TARGET := iphone:clang:16.5:15.0
INSTALL_TARGET_PROCESSES = Argo
ARCHS = arm64
THEOS_PACKAGE_SCHEME = rootless

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = AppbootKeyExtract

AppbootKeyExtract_FILES = $(shell find Sources/AppbootKeyExtract -name '*.swift') $(shell find Sources/AppbootKeyExtractC -name '*.m' -o -name '*.c' -o -name '*.mm' -o -name '*.cpp')
AppbootKeyExtract_SWIFTFLAGS = -ISources/AppbootKeyExtractC/include
AppbootKeyExtract_CFLAGS = -fobjc-arc -ISources/AppbootKeyExtractC/include -Wno-unused-function
AppbootKeyExtract_FRAMEWORKS = Foundation
AppbootKeyExtract_LDFLAGS = -lsubstrate

include $(THEOS_MAKE_PATH)/tweak.mk

after-install::
	install.exec "chmod 755 /var/jb/Library/MobileSubstrate/DynamicLibraries/AppbootKeyExtract.dylib"
