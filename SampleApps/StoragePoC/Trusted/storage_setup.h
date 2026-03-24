#pragma once

#include <vector>

namespace storagepoc::trusted::setup
{
HRESULT ProvisionProtectedKeyMaterial(
    _In_ uint32_t activityLevel,
    _In_ const std::wstring& logFilePath,
    _Out_ std::vector<uint8_t>& protectedKeyMaterialBlob);
}
