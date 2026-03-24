#include "pch.h"

#include "storage_setup.h"

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

        // Step 2: Protect S for VTL0 persistence.
        // TODO(storage-poc): Replace direct enclave seal with KDF-derived sealkey flow.
        auto sealed = veil::vtl1::crypto::seal_data(
            symmetricKeyBytes,
            ENCLAVE_IDENTITY_POLICY_SEAL_SAME_IMAGE,
            0);

        protectedKeyMaterialBlob.assign(sealed.begin(), sealed.end());

        // TODO(storage-poc): Define setup metadata schema and versioning strategy.
        setupMetadataBlob = {'S', 'P', 'O', 'C', 'v', '1'};

        return S_OK;
    }
    CATCH_RETURN();
}
} // namespace storagepoc::trusted::setup
