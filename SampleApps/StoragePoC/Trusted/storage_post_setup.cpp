#include "pch.h"

#include "storage_post_setup.h"

#include <veil/enclave/crypto.vtl1.h>

namespace storagepoc::trusted::post_setup
{
namespace
{
wil::secure_vector<uint8_t> LoadSymmetricKeyBytes(
    _In_ const std::vector<uint8_t>& protectedKeyMaterialBlob,
    _Out_ std::vector<uint8_t>& maybeResealedKeyMaterialBlob)
{
    auto [unsealedKey, unsealingFlags] = veil::vtl1::crypto::unseal_data(protectedKeyMaterialBlob);

    // TODO(storage-poc): Handle stale key policy explicitly and reseal as needed.
    if ((unsealingFlags & ENCLAVE_UNSEAL_FLAG_STALE_KEY) != 0)
    {
        auto resealed = veil::vtl1::crypto::seal_data(
            unsealedKey,
            ENCLAVE_IDENTITY_POLICY_SEAL_SAME_IMAGE,
            0);
        maybeResealedKeyMaterialBlob.assign(resealed.begin(), resealed.end());
    }

    return unsealedKey;
}
} // namespace

HRESULT EncryptPayload(
    _In_ const std::vector<uint8_t>& protectedKeyMaterialBlob,
    _In_ const std::vector<uint8_t>& plaintextPayload,
    _In_ uint32_t /*activityLevel*/,
    _In_ const std::wstring& /*logFilePath*/,
    _Out_ std::vector<uint8_t>& maybeResealedKeyMaterialBlob,
    _Out_ std::vector<uint8_t>& ciphertextPayload,
    _Out_ std::vector<uint8_t>& payloadTag,
    _Out_ std::vector<uint8_t>& payloadMetadataBlob)
{
    try
    {
        auto keyBytes = LoadSymmetricKeyBytes(protectedKeyMaterialBlob, maybeResealedKeyMaterialBlob);
        auto symmetricKey = veil::vtl1::crypto::create_symmetric_key(keyBytes);

        // TODO(storage-poc): Replace fixed nonce strategy with per-record nonce + AAD.
        auto [ciphertext, tag] = veil::vtl1::crypto::encrypt(
            symmetricKey.get(),
            plaintextPayload,
            veil::vtl1::crypto::zero_nonce);

        ciphertextPayload.assign(ciphertext.begin(), ciphertext.end());
        payloadTag.assign(tag.begin(), tag.end());

        // TODO(storage-poc): Define metadata format (version, nonce, aad hash, etc.).
        payloadMetadataBlob = {'P', 'L', 'D', 'v', '1'};

        return S_OK;
    }
    CATCH_RETURN();
}

HRESULT DecryptPayload(
    _In_ const std::vector<uint8_t>& protectedKeyMaterialBlob,
    _In_ const std::vector<uint8_t>& ciphertextPayload,
    _In_ const std::vector<uint8_t>& payloadTag,
    _In_ const std::vector<uint8_t>& payloadMetadataBlob,
    _In_ uint32_t /*activityLevel*/,
    _In_ const std::wstring& /*logFilePath*/,
    _Out_ std::vector<uint8_t>& maybeResealedKeyMaterialBlob,
    _Out_ std::vector<uint8_t>& plaintextPayload)
{
    try
    {
        (void)payloadMetadataBlob;
        // TODO(storage-poc): Validate metadata version and integrity rules before decrypting.

        auto keyBytes = LoadSymmetricKeyBytes(protectedKeyMaterialBlob, maybeResealedKeyMaterialBlob);
        auto symmetricKey = veil::vtl1::crypto::create_symmetric_key(keyBytes);

        auto plaintext = veil::vtl1::crypto::decrypt(
            symmetricKey.get(),
            ciphertextPayload,
            veil::vtl1::crypto::zero_nonce,
            payloadTag);

        plaintextPayload.assign(plaintext.begin(), plaintext.end());
        return S_OK;
    }
    CATCH_RETURN();
}
} // namespace storagepoc::trusted::post_setup
