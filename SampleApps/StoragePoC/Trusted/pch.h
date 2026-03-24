#pragma once

#include <wil/enclave/wil_for_enclaves.h>

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include <wil/result.h>
#include <wil/result_macros.h>
#include <wil/stl.h>

#ifndef ENCLAVE_FLAG_FULL_DEBUG_ENABLED
#define ENCLAVE_FLAG_FULL_DEBUG_ENABLED 0x00000002
#endif

#ifndef ENCLAVE_IDENTITY_POLICY_SEAL_SAME_IMAGE
#define ENCLAVE_IDENTITY_POLICY_SEAL_SAME_IMAGE static_cast<ENCLAVE_SEALING_IDENTITY_POLICY>(1)
#endif

#ifndef ENCLAVE_UNSEAL_FLAG_STALE_KEY
#define ENCLAVE_UNSEAL_FLAG_STALE_KEY 0x00000001
#endif
