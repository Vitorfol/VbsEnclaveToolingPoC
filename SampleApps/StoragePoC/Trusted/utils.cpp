#include "pch.h"

#include "utils.h"

#include <array>
#include <cstring>

#include <veil/enclave/crypto.vtl1.h>
#include <veil/enclave/utils.vtl1.h>

namespace storagepoc::trusted::utils
{
namespace
{
constexpr uint32_t kProtectedBlobVersion = 1;
constexpr std::array<uint8_t, 8> kBlobMagic = {'S', 'P', 'O', 'C', 'K', 'E', 'Y', '1'};

std::vector<uint8_t> HashSha384(_In_ std::span<const uint8_t> data)
{
	wil::unique_bcrypt_hash hash;
	THROW_IF_NTSTATUS_FAILED(BCryptCreateHash(BCRYPT_SHA384_ALG_HANDLE, &hash, nullptr, 0, nullptr, 0, 0));
  THROW_IF_NTSTATUS_FAILED(BCryptHashData(hash.get(), const_cast<PUCHAR>(data.data()), gsl::narrow_cast<ULONG>(data.size()), 0));

	ULONG hashSize = 0;
	ULONG resultSize = 0;
	THROW_IF_NTSTATUS_FAILED(BCryptGetProperty(BCRYPT_SHA384_ALG_HANDLE, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hashSize), sizeof(hashSize), &resultSize, 0));

	std::vector<uint8_t> digest(hashSize);
	THROW_IF_NTSTATUS_FAILED(BCryptFinishHash(hash.get(), digest.data(), hashSize, 0));
	return digest;
}

void AppendUint32(_Inout_ std::vector<uint8_t>& target, _In_ uint32_t value)
{
	const auto p = reinterpret_cast<const uint8_t*>(&value);
	target.insert(target.end(), p, p + sizeof(value));
}

uint32_t ReadUint32(_In_ std::span<const uint8_t> source, _Inout_ size_t& offset)
{
	THROW_HR_IF(E_INVALIDARG, offset + sizeof(uint32_t) > source.size());
	uint32_t value = 0;
	std::memcpy(&value, source.data() + offset, sizeof(uint32_t));
	offset += sizeof(uint32_t);
	return value;
}

std::vector<uint8_t> BuildSealedPayload(
	_In_ std::span<const uint8_t> symmetricKeyBytes,
	_In_ std::span<const uint8_t> mrenclaveHash)
{
	std::vector<uint8_t> payload;
	payload.reserve(
		kBlobMagic.size() +
		sizeof(uint32_t) +
		sizeof(uint32_t) +
		mrenclaveHash.size() +
		sizeof(uint32_t) +
		symmetricKeyBytes.size());

	payload.insert(payload.end(), kBlobMagic.begin(), kBlobMagic.end());
	AppendUint32(payload, kProtectedBlobVersion);
	AppendUint32(payload, static_cast<uint32_t>(mrenclaveHash.size()));
	payload.insert(payload.end(), mrenclaveHash.begin(), mrenclaveHash.end());
	AppendUint32(payload, static_cast<uint32_t>(symmetricKeyBytes.size()));
	payload.insert(payload.end(), symmetricKeyBytes.begin(), symmetricKeyBytes.end());

	return payload;
}
} // namespace

std::vector<uint8_t> ComputeMrenclaveHashMaterial()
{
	auto& identity = veil::vtl1::enclave_information().Identity;
	auto identityBytes = std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(&identity), sizeof(identity));

	// NOTE: The sealing operation already binds to platform-protected secret material.
	return HashSha384(identityBytes);
}

std::vector<uint8_t> CreateProtectedSymmetricKeyBlob(
	_In_ std::span<const uint8_t> symmetricKeyBytes,
	_In_ std::span<const uint8_t> mrenclaveHash)
{
	auto payload = BuildSealedPayload(symmetricKeyBytes, mrenclaveHash);
	auto sealed = veil::vtl1::crypto::seal_data(
		payload,
		ENCLAVE_IDENTITY_POLICY_SEAL_SAME_IMAGE,
		0);
	return std::vector<uint8_t>(sealed.begin(), sealed.end());
}

wil::secure_vector<uint8_t> RecoverSymmetricKeyFromProtectedBlob(
	_In_ std::span<const uint8_t> protectedBlob,
	_In_ std::span<const uint8_t> expectedMrenclaveHash,
	_Out_ std::vector<uint8_t>& maybeResealedBlob)
{
	auto [unsealedPayload, unsealingFlags] = veil::vtl1::crypto::unseal_data(protectedBlob);

	if ((unsealingFlags & ENCLAVE_UNSEAL_FLAG_STALE_KEY) != 0)
	{
		auto resealed = veil::vtl1::crypto::seal_data(
			unsealedPayload,
			ENCLAVE_IDENTITY_POLICY_SEAL_SAME_IMAGE,
			0);
		maybeResealedBlob.assign(resealed.begin(), resealed.end());
	}

	THROW_HR_IF(E_INVALIDARG, unsealedPayload.size() < kBlobMagic.size() + sizeof(uint32_t) * 3);
	THROW_HR_IF(E_ACCESSDENIED,
		!std::equal(kBlobMagic.begin(), kBlobMagic.end(), unsealedPayload.begin()));

	size_t offset = kBlobMagic.size();
	const auto version = ReadUint32(unsealedPayload, offset);
	THROW_HR_IF(E_NOTIMPL, version != kProtectedBlobVersion);

	const auto mrenclaveSize = ReadUint32(unsealedPayload, offset);
	THROW_HR_IF(E_INVALIDARG, offset + mrenclaveSize > unsealedPayload.size());
	std::span<const uint8_t> blobMrenclave(unsealedPayload.data() + offset, mrenclaveSize);
	offset += mrenclaveSize;

	THROW_HR_IF(E_ACCESSDENIED,
		blobMrenclave.size() != expectedMrenclaveHash.size() ||
		std::memcmp(blobMrenclave.data(), expectedMrenclaveHash.data(), blobMrenclave.size()) != 0);

	const auto symmetricKeySize = ReadUint32(unsealedPayload, offset);
	THROW_HR_IF(E_INVALIDARG, offset + symmetricKeySize > unsealedPayload.size());

	wil::secure_vector<uint8_t> keyBytes;
	keyBytes.assign(
		unsealedPayload.begin() + offset,
		unsealedPayload.begin() + offset + symmetricKeySize);
	return keyBytes;
}
}
