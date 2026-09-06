package proxy

/*
#include <stdlib.h>
#include <string.h>
*/
import "C"
import "unsafe"

// Global exclusion manager instance for Android VPN.
var androidExcludeManager = NewAndroidVPNExclusionManager()

//export Java_com_github_shadowsocks_plugin_v2ray_BinaryProvider_excludePackage
func Java_com_github_shadowsocks_plugin_v2ray_BinaryProvider_excludePackage(env unsafe.Pointer, class unsafe.Pointer, pkgName *C.char) {
	if pkgName == nil {
		return
	}
	goPkgName := C.GoString(pkgName)
	androidExcludeManager.SetExcludedPackages(append(androidExcludeManager.GetExcludeList(), goPkgName))
}

//export Java_com_github_shadowsocks_plugin_v2ray_BinaryProvider_isPackageExcluded
func Java_com_github_shadowsocks_plugin_v2ray_BinaryProvider_isPackageExcluded(env unsafe.Pointer, class unsafe.Pointer, pkgName *C.char) C.int {
	if pkgName == nil {
		return 0
	}
	goPkgName := C.GoString(pkgName)
	if androidExcludeManager.IsPackageExcluded(goPkgName) {
		return 1
	}
	return 0
}

//export Java_com_github_shadowsocks_plugin_v2ray_BinaryProvider_clearExclusions
func Java_com_github_shadowsocks_plugin_v2ray_BinaryProvider_clearExclusions(env unsafe.Pointer, class unsafe.Pointer) {
	androidExcludeManager.SetExcludedPackages(nil)
}
