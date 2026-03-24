#include "pch.h"

#include "storage_setup.h"
#include "utils.h"

#include <veil/enclave/crypto.vtl1.h>

namespace storagepoc::trusted::setup
{
HRESULT ProvisionProtectedKeyMaterial(
    _In_ uint32_t /*activityLevel*/,
    _In_ const std::wstring& /*logFilePath*/,
    _Out_ std::vector<uint8_t>& protectedKeyMaterialBlob,
    _Out_ std::vector<uint8_t>& setupMetadataBlob)
{
    try
    {
        // Step 1: Generate symmetric key S inside VTL1.
        auto symmetricKeyBytes = veil::vtl1::crypto::generate_symmetric_key_bytes();

        // Step 2: Get mrenclave hash material for explicit binding.
        auto mrenclaveHash = storagepoc::trusted::utils::ComputeMrenclaveHashMaterial();

        // Step 3: Protect S with hardware-rooted enclave sealing and mrenclave-bound payload.
        auto wrappedKeyBlob = storagepoc::trusted::utils::CreateProtectedSymmetricKeyBlob(
            symmetricKeyBytes,
            mrenclaveHash);
        protectedKeyMaterialBlob.assign(wrappedKeyBlob.begin(), wrappedKeyBlob.end());

        // TODO(storage-poc): Define setup metadata schema and versioning strategy.
        // For now expose mrenclave hash bytes as setup metadata to aid flow verification.
        setupMetadataBlob = mrenclaveHash;

        return S_OK;
    }
    CATCH_RETURN();
}
} // namespace storagepoc::trusted::setup
