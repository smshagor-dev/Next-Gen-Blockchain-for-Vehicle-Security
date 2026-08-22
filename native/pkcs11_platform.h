#pragma once

// OASIS PKCS #11 v3.2 section 2.2 requires applications to provide five
// platform/compiler macros before including <pkcs11.h>. Keep the defaults
// conservative and overridable so integrators may provide ABI-specific forms.
#ifndef CK_PTR
#define CK_PTR *
#endif

#ifndef CK_DECLARE_FUNCTION
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#endif

#ifndef CK_DECLARE_FUNCTION_POINTER
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (*name)
#endif

#ifndef CK_CALLBACK_FUNCTION
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (*name)
#endif

#ifndef NULL_PTR
#define NULL_PTR 0
#endif

// Cryptoki structures use one-byte packing on Windows. The canonical OASIS
// header leaves this platform choice to the application.
#if defined(_WIN32)
#pragma pack(push, cryptoki, 1)
#endif

#include <pkcs11.h>

#if defined(_WIN32)
#pragma pack(pop, cryptoki)
#endif
