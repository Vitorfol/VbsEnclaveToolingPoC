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

        // Step 2: Derive seal key K from mrenclave material.
        auto mrenclaveHash = storagepoc::trusted::utils::ComputeMrenclaveHashMaterial();
        auto sealKeyBytes = storagepoc::trusted::utils::DeriveSealKeyFromMrenclave(mrenclaveHash);

        // Step 3: Encrypt S with K and return opaque blob to VTL0 for persistence.
        auto wrappedKeyBlob = storagepoc::trusted::utils::EncryptSymmetricKeyWithSealKey(
            symmetricKeyBytes,
            sealKeyBytes);
        protectedKeyMaterialBlob.assign(wrappedKeyBlob.begin(), wrappedKeyBlob.end());

        // TODO(storage-poc): Define setup metadata schema and versioning strategy.
        // For now expose mrenclave hash bytes as setup metadata to aid flow verification.
        setupMetadataBlob = mrenclaveHash;

        return S_OK;
    }
    CATCH_RETURN();
}
} // namespace storagepoc::trusted::setup
