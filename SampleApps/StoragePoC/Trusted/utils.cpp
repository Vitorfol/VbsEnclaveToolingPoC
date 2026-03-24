#include "pch.h"

#include "utils.h"

#include <array>

#include <veil/enclave/crypto.vtl1.h>
#include <veil/enclave/utils.vtl1.h>

namespace storagepoc::trusted::utils
{
namespace
{
std::vector<uint8_t> HashSha384(_In_ std::span<const uint8_t> data)
{
	wil::unique_bcrypt_hash hash;
	THROW_IF_NTSTATUS_FAILED(BCryptCreateHash(BCRYPT_SHA384_ALG_HANDLE, &hash, nullptr, 0, nullptr, 0, 0));
	THROW_IF_NTSTATUS_FAILED(BCryptHashData(hash.get(), const_cast<PUCHAR>(data.data()), veil::vtl1::narrow_cast<ULONG>(data.size()), 0));

	ULONG hashSize = 0;
	ULONG resultSize = 0;
	THROW_IF_NTSTATUS_FAILED(BCryptGetProperty(BCRYPT_SHA384_ALG_HANDLE, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hashSize), sizeof(hashSize), &resultSize, 0));

	std::vector<uint8_t> digest(hashSize);
	THROW_IF_NTSTATUS_FAILED(BCryptFinishHash(hash.get(), digest.data(), hashSize, 0));
	return digest;
}

std::vector<uint8_t> BuildSealKeyDerivationInput(_In_ std::span<const uint8_t> mrenclaveHash)
{
	constexpr std::array<uint8_t, 20> domainSeparator = {
		'S', 't', 'o', 'r', 'a', 'g', 'e', 'P', 'o', 'C',
		'.', 'S', 'e', 'a', 'l', 'K', 'e', 'y', '.', '1'};

	std::vector<uint8_t> input;
	input.reserve(domainSeparator.size() + mrenclaveHash.size());
	input.insert(input.end(), domainSeparator.begin(), domainSeparator.end());
	input.insert(input.end(), mrenclaveHash.begin(), mrenclaveHash.end());
	return input;
}
} // namespace

std::vector<uint8_t> ComputeMrenclaveHashMaterial()
{
	auto& identity = veil::vtl1::enclave_information().Identity;
	auto identityBytes = std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(&identity), sizeof(identity));

	// TODO(storage-poc): Mix hardware secret material from processor/TPM into the derivation input.
	return HashSha384(identityBytes);
}

wil::secure_vector<uint8_t> DeriveSealKeyFromMrenclave(_In_ std::span<const uint8_t> mrenclaveHash)
{
	auto derivationInput = BuildSealKeyDerivationInput(mrenclaveHash);
	auto digest = HashSha384(derivationInput);

	// Use the first 32 bytes for AES-256 key bytes.
	THROW_HR_IF(E_UNEXPECTED, digest.size() < veil::vtl1::crypto::SYMMETRIC_KEY_SIZE_BYTES);
	wil::secure_vector<uint8_t> sealKeyBytes;
	sealKeyBytes.assign(
		digest.begin(),
		digest.begin() + veil::vtl1::crypto::SYMMETRIC_KEY_SIZE_BYTES);
	return sealKeyBytes;
}

std::vector<uint8_t> EncryptSymmetricKeyWithSealKey(
	_In_ std::span<const uint8_t> symmetricKeyBytes,
	_In_ std::span<const uint8_t> sealKeyBytes)
{
	auto sealKey = veil::vtl1::crypto::create_symmetric_key(sealKeyBytes);
	auto wrapped = veil::vtl1::crypto::encrypt_and_tag(sealKey.get(), symmetricKeyBytes);
	return std::vector<uint8_t>(wrapped.begin(), wrapped.end());
}

wil::secure_vector<uint8_t> DecryptSymmetricKeyWithSealKey(
	_In_ std::span<const uint8_t> encryptedSymmetricKeyBlob,
	_In_ std::span<const uint8_t> sealKeyBytes)
{
	auto sealKey = veil::vtl1::crypto::create_symmetric_key(sealKeyBytes);
	return veil::vtl1::crypto::decrypt_and_untag(sealKey.get(), encryptedSymmetricKeyBlob);
}
}
