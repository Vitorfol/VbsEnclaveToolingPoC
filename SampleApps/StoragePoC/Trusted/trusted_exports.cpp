#include "pch.h"

#include "storage_post_setup.h"
#include "storage_setup.h"
#include "utils.h"

namespace VbsEnclave::Trusted::Implementation
{
HRESULT StoragePocCommon_GetMrenclaveHash(
    _In_ const uint32_t /*activity_level*/,
    _In_ const std::wstring& /*log_file_path*/,
    _Out_ std::vector<std::uint8_t>& mrenclave_hash_material)
{
    try
    {
        mrenclave_hash_material = storagepoc::trusted::utils::ComputeMrenclaveHashMaterial();
        return S_OK;
    }
    CATCH_RETURN();
}

HRESULT StoragePocSetup_ProvisionKeyMaterial(
    _In_ const uint32_t activity_level,
    _In_ const std::wstring& log_file_path,
    _Out_ std::vector<std::uint8_t>& protected_key_material_blob)
{
    return storagepoc::trusted::setup::ProvisionProtectedKeyMaterial(
        activity_level,
        log_file_path,
        protected_key_material_blob);
}

HRESULT StoragePocPostSetup_EncryptPayload(
    _In_ const std::vector<std::uint8_t>& protected_key_material_blob,
    _In_ const std::vector<std::uint8_t>& plaintext_payload,
    _In_ const uint32_t activity_level,
    _In_ const std::wstring& log_file_path,
    _Out_ std::vector<std::uint8_t>& maybe_resealed_key_material_blob,
    _Out_ std::vector<std::uint8_t>& ciphertext_payload,
    _Out_ std::vector<std::uint8_t>& payload_tag,
    _Out_ std::vector<std::uint8_t>& payload_metadata_blob)
{
    return storagepoc::trusted::post_setup::EncryptPayload(
        protected_key_material_blob,
        plaintext_payload,
        activity_level,
        log_file_path,
        maybe_resealed_key_material_blob,
        ciphertext_payload,
        payload_tag,
        payload_metadata_blob);
}

HRESULT StoragePocPostSetup_DecryptPayload(
    _In_ const std::vector<std::uint8_t>& protected_key_material_blob,
    _In_ const std::vector<std::uint8_t>& ciphertext_payload,
    _In_ const std::vector<std::uint8_t>& payload_tag,
    _In_ const std::vector<std::uint8_t>& payload_metadata_blob,
    _In_ const uint32_t activity_level,
    _In_ const std::wstring& log_file_path,
    _Out_ std::vector<std::uint8_t>& maybe_resealed_key_material_blob,
    _Out_ std::vector<std::uint8_t>& plaintext_payload)
{
    return storagepoc::trusted::post_setup::DecryptPayload(
        protected_key_material_blob,
        ciphertext_payload,
        payload_tag,
        payload_metadata_blob,
        activity_level,
        log_file_path,
        maybe_resealed_key_material_blob,
        plaintext_payload);
}

} // namespace VbsEnclave::Trusted::Implementation
