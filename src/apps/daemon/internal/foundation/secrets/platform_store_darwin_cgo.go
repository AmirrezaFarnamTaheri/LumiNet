//go:build darwin && cgo

package secrets

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdlib.h>
#include <string.h>

static const char *luminet_service = "LumiNet";

static CFStringRef luminet_string(const char *value) {
	return CFStringCreateWithCString(kCFAllocatorDefault, value, kCFStringEncodingUTF8);
}

static CFDictionaryRef luminet_query(const char *account, Boolean return_data, Boolean return_attributes, CFTypeRef match_limit) {
	CFStringRef service = luminet_string(luminet_service);
	CFStringRef account_value = account ? luminet_string(account) : NULL;
	const void *keys[6] = { kSecClass, kSecAttrService, kSecAttrAccount, kSecReturnData, kSecReturnAttributes, kSecMatchLimit };
	const void *values[6] = { kSecClassGenericPassword, service, account_value, return_data ? kCFBooleanTrue : kCFBooleanFalse, return_attributes ? kCFBooleanTrue : kCFBooleanFalse, match_limit ? match_limit : kSecMatchLimitOne };
	CFIndex count = account ? 6 : 5;
	if (!account) {
		keys[2] = kSecReturnData;
		keys[3] = kSecReturnAttributes;
		keys[4] = kSecMatchLimit;
		values[2] = return_data ? kCFBooleanTrue : kCFBooleanFalse;
		values[3] = return_attributes ? kCFBooleanTrue : kCFBooleanFalse;
		values[4] = match_limit ? match_limit : kSecMatchLimitOne;
	}
	CFDictionaryRef query = CFDictionaryCreate(kCFAllocatorDefault, keys, values, count, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFRelease(service);
	if (account_value) CFRelease(account_value);
	return query;
}

static OSStatus luminet_keychain_put(const char *account, const void *data, CFIndex data_len) {
	CFDictionaryRef query = luminet_query(account, false, false, kSecMatchLimitOne);
	CFDataRef value_data = CFDataCreate(kCFAllocatorDefault, data, data_len);
	const void *keys[] = { kSecValueData };
	const void *values[] = { value_data };
	CFDictionaryRef updates = CFDictionaryCreate(kCFAllocatorDefault, keys, values, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	OSStatus status = SecItemUpdate(query, updates);
	if (status == errSecItemNotFound) {
		const void *add_keys[] = { kSecClass, kSecAttrService, kSecAttrAccount, kSecValueData };
		CFStringRef service = luminet_string(luminet_service);
		CFStringRef account_value = luminet_string(account);
		const void *add_values[] = { kSecClassGenericPassword, service, account_value, value_data };
		CFDictionaryRef add = CFDictionaryCreate(kCFAllocatorDefault, add_keys, add_values, 4, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
		status = SecItemAdd(add, NULL);
		CFRelease(add);
		CFRelease(service);
		CFRelease(account_value);
	}
	CFRelease(updates);
	CFRelease(value_data);
	CFRelease(query);
	return status;
}

static OSStatus luminet_keychain_get(const char *account, void **out, CFIndex *out_len) {
	*out = NULL;
	*out_len = 0;
	CFDictionaryRef query = luminet_query(account, true, false, kSecMatchLimitOne);
	CFTypeRef result = NULL;
	OSStatus status = SecItemCopyMatching(query, &result);
	CFRelease(query);
	if (status != errSecSuccess) return status;
	if (CFGetTypeID(result) != CFDataGetTypeID()) { CFRelease(result); return errSecDecode; }
	CFDataRef data = (CFDataRef)result;
	CFIndex length = CFDataGetLength(data);
	void *copy = malloc(length > 0 ? (size_t)length : 1);
	if (copy == NULL) { CFRelease(result); return errSecAllocate; }
	if (length > 0) memcpy(copy, CFDataGetBytePtr(data), (size_t)length);
	*out = copy;
	*out_len = length;
	CFRelease(result);
	return errSecSuccess;
}

static OSStatus luminet_keychain_delete(const char *account) {
	CFDictionaryRef query = luminet_query(account, false, false, kSecMatchLimitOne);
	OSStatus status = SecItemDelete(query);
	CFRelease(query);
	return status;
}

static OSStatus luminet_keychain_list(void **out, CFIndex *out_len) {
	*out = NULL;
	*out_len = 0;
	CFDictionaryRef query = luminet_query(NULL, false, true, kSecMatchLimitAll);
	CFTypeRef result = NULL;
	OSStatus status = SecItemCopyMatching(query, &result);
	CFRelease(query);
	if (status == errSecItemNotFound) return errSecSuccess;
	if (status != errSecSuccess) return status;
	if (CFGetTypeID(result) != CFArrayGetTypeID()) { CFRelease(result); return errSecDecode; }
	CFArrayRef items = (CFArrayRef)result;
	CFIndex total = 0;
	for (CFIndex i = 0; i < CFArrayGetCount(items); i++) {
		CFDictionaryRef item = (CFDictionaryRef)CFArrayGetValueAtIndex(items, i);
		CFStringRef account = (CFStringRef)CFDictionaryGetValue(item, kSecAttrAccount);
		if (account) total += CFStringGetMaximumSizeForEncoding(CFStringGetLength(account), kCFStringEncodingUTF8) + 1;
	}
	if (total == 0) { CFRelease(result); return errSecSuccess; }
	char *copy = malloc((size_t)total);
	if (copy == NULL) { CFRelease(result); return errSecAllocate; }
	CFIndex offset = 0;
	for (CFIndex i = 0; i < CFArrayGetCount(items); i++) {
		CFDictionaryRef item = (CFDictionaryRef)CFArrayGetValueAtIndex(items, i);
		CFStringRef account = (CFStringRef)CFDictionaryGetValue(item, kSecAttrAccount);
		if (account) {
			CFIndex capacity = total - offset;
			if (CFStringGetCString(account, copy + offset, capacity, kCFStringEncodingUTF8)) offset += (CFIndex)strlen(copy + offset) + 1;
		}
	}
	*out = copy;
	*out_len = offset;
	CFRelease(result);
	return errSecSuccess;
}
*/
import "C"

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"unsafe"
)

const keychainItemNotFound = -25300 // errSecItemNotFound

// KeychainStore uses macOS Keychain Services generic-password entries scoped to
// the LumiNet service. The operating system encrypts and access-controls the
// values; no plaintext or locally-derived encryption key is written by this
// provider.
type KeychainStore struct{ mu sync.Mutex }

func newPlatformStore() (NativeStore, error) { return &KeychainStore{}, nil }

func (*KeychainStore) ProviderName() string { return "keychain" }
func (*KeychainStore) Native() bool         { return true }

func (s *KeychainStore) Put(ctx context.Context, ref string, value []byte) error {
	if err := validNativeRef(ref); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	account := C.CString(ref)
	defer C.free(unsafe.Pointer(account))
	var data unsafe.Pointer
	if len(value) > 0 {
		data = unsafe.Pointer(&value[0])
	}
	if status := C.luminet_keychain_put(account, data, C.CFIndex(len(value))); status != C.errSecSuccess {
		return keychainStatus("store", ref, status)
	}
	return nil
}

func (s *KeychainStore) Get(ctx context.Context, ref string) ([]byte, error) {
	if err := validNativeRef(ref); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	account := C.CString(ref)
	defer C.free(unsafe.Pointer(account))
	var data unsafe.Pointer
	var length C.CFIndex
	status := C.luminet_keychain_get(account, &data, &length)
	if status == C.OSStatus(keychainItemNotFound) {
		return nil, ErrNotFound{Ref: ref}
	}
	if status != C.errSecSuccess {
		return nil, keychainStatus("retrieve", ref, status)
	}
	defer C.free(data)
	return C.GoBytes(data, C.int(length)), nil
}

func (s *KeychainStore) Delete(ctx context.Context, ref string) error {
	if err := validNativeRef(ref); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	account := C.CString(ref)
	defer C.free(unsafe.Pointer(account))
	status := C.luminet_keychain_delete(account)
	if status == C.OSStatus(keychainItemNotFound) || status == C.errSecSuccess {
		return nil
	}
	return keychainStatus("delete", ref, status)
}

func (s *KeychainStore) List(ctx context.Context) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var data unsafe.Pointer
	var length C.CFIndex
	if status := C.luminet_keychain_list(&data, &length); status != C.errSecSuccess {
		return nil, keychainStatus("list", "", status)
	}
	if data == nil || length == 0 {
		return nil, nil
	}
	defer C.free(data)
	refs := strings.FieldsFunc(string(C.GoBytes(data, C.int(length))), func(r rune) bool { return r == 0 })
	sort.Strings(refs)
	return refs, nil
}

func keychainStatus(operation, ref string, status C.OSStatus) error {
	if ref == "" {
		return fmt.Errorf("secrets/keychain: %s failed with OSStatus %d", operation, int32(status))
	}
	return fmt.Errorf("secrets/keychain: %s %q failed with OSStatus %d", operation, ref, int32(status))
}

var _ NativeStore = (*KeychainStore)(nil)
