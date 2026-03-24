#pragma once

#include <span>
#include <vector>

#include <wil/stl.h>

namespace storagepoc::trusted::utils
{
std::vector<uint8_t> ComputeMrenclaveHashMaterial();

std::vector<uint8_t> CreateProtectedSymmetricKeyBlob(
	_In_ std::span<const uint8_t> symmetricKeyBytes,
	_In_ std::span<const uint8_t> mrenclaveHash);

wil::secure_vector<uint8_t> RecoverSymmetricKeyFromProtectedBlob(
	_In_ std::span<const uint8_t> protectedBlob,
	_In_ std::span<const uint8_t> expectedMrenclaveHash,
	_Out_ std::vector<uint8_t>& maybeResealedBlob);
}
