#pragma once

#include <span>
#include <vector>

#include <wil/stl.h>

namespace storagepoc::trusted::utils
{
std::vector<uint8_t> ComputeMrenclaveHashMaterial();

wil::secure_vector<uint8_t> DeriveSealKeyFromMrenclave(_In_ std::span<const uint8_t> mrenclaveHash);

std::vector<uint8_t> EncryptSymmetricKeyWithSealKey(
	_In_ std::span<const uint8_t> symmetricKeyBytes,
	_In_ std::span<const uint8_t> sealKeyBytes);

wil::secure_vector<uint8_t> DecryptSymmetricKeyWithSealKey(
	_In_ std::span<const uint8_t> encryptedSymmetricKeyBlob,
	_In_ std::span<const uint8_t> sealKeyBytes);
}
