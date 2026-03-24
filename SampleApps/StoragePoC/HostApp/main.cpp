#include <iostream>
#include <filesystem>
#include <limits>
#include <string>

#include <wil/result_macros.h>

#include <veil/host/enclave_api.vtl0.h>
#include <veil/host/logger.vtl0.h>

#include "StorageFlowHandler.h"

namespace fs = std::filesystem;

namespace
{
storagepoc::host::StorageArtifactPaths BuildDefaultPaths(_In_ const fs::path& root)
{
	return {
		root / "protected_key_material.bin",
		root / "payload_ciphertext.bin",
		root / "payload_tag.bin",
		root / "payload_metadata.bin",
		root / "setup_metadata.bin",
	};
}

std::vector<uint8_t> ToUtf8Bytes(_In_ const std::wstring& text)
{
	// Placeholder conversion for the template. This will be replaced by an encoding-safe implementation.
	return std::vector<uint8_t>(text.begin(), text.end());
}

std::wstring FromUtf8Bytes(_In_ std::span<const uint8_t> data)
{
	// Placeholder conversion for the template. This will be replaced by an encoding-safe implementation.
	return std::wstring(data.begin(), data.end());
}
}

int main(int argc, char* argv[])
{
	if (argc > 2)
	{
		std::cerr << "Usage: " << argv[0] << " <logging_level>" << std::endl;
		std::cerr << "Logging levels: 1 - Critical, 2 - Error, 3 - Warning, 4 - Info, 5 - Verbose" << std::endl;
		return 1;
	}

	uint32_t activityLevel = (argc == 2) ? static_cast<uint32_t>(std::atoi(argv[1])) : 4;

	veil::vtl0::logger::logger veilLog(
		L"StoragePoCHostApp",
		L"1A2B3C4D-1111-2222-3333-444455556666",
		static_cast<veil::any::logger::eventLevel>(activityLevel));

	std::vector<uint8_t> ownerId = {};
	auto flags = ENCLAVE_VBS_FLAG_DEBUG;

	auto enclave = veil::vtl0::enclave::create(ENCLAVE_TYPE_VBS, ownerId, flags, veil::vtl0::enclave::megabytes(512));
	veil::vtl0::enclave::load_image(enclave.get(), L"storagepoc.dll");
	veil::vtl0::enclave::initialize(enclave.get(), 2);
	veil::vtl0::enclave_api::register_callbacks(enclave.get());

	auto paths = BuildDefaultPaths(fs::current_path());

	while (true)
	{
		std::cout << "\n*** Storage PoC Menu ***\n";
		std::cout << "1. Setup (provision key material S)\n";
		std::cout << "2. Post-setup Encrypt and Persist\n";
		std::cout << "3. Post-setup Load and Decrypt\n";
		std::cout << "4. Exit\n";
		std::cout << "Enter your choice: ";

		int choice = 0;
		if (!(std::cin >> choice))
		{
			std::cout << "Invalid input. Please enter a valid option (1-4).\n";
			std::cin.clear();
			std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
			continue;
		}

		try
		{
			if (choice == 1)
			{
				THROW_IF_FAILED(storagepoc::host::RunSetupFlow(enclave.get(), paths, veilLog));
				std::wcout << L"Setup finalizado. Blob protegido de S persistido em disco." << std::endl;
			}
			else if (choice == 2)
			{
				std::wcout << L"Digite o payload para criptografar: ";
				std::wcin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
				std::wstring input;
				std::getline(std::wcin, input);

				auto payload = ToUtf8Bytes(input);
				THROW_IF_FAILED(storagepoc::host::RunPostSetupEncryptFlow(enclave.get(), paths, payload, veilLog));
				std::wcout << L"Encrypt pos-setup finalizado. Ciphertext persistido em disco." << std::endl;
			}
			else if (choice == 3)
			{
				std::vector<uint8_t> plaintext;
				THROW_IF_FAILED(storagepoc::host::RunPostSetupDecryptFlow(enclave.get(), paths, plaintext, veilLog));
				auto decoded = FromUtf8Bytes(plaintext);
				std::wcout << L"Decrypt pos-setup finalizado. Payload recuperado: " << decoded << std::endl;
			}
			else if (choice == 4)
			{
				std::cout << "Exiting program...\n";
				break;
			}
			else
			{
				std::cout << "Invalid choice. Please try again.\n";
			}
		}
		catch (...)
		{
			std::wcout << L"Erro no fluxo. Verifique logs e artefatos persistidos." << std::endl;
		}
	}

	return 0;
}
