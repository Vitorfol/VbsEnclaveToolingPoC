#include <iostream>
#include <filesystem>
#include <cstdlib>
#include <limits>
#include <string>
#include <vector>

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
		root / "blob.txt",
		root / "data.txt",
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
	if (argc > 3)
	{
		std::cerr << "Usage: " << argv[0] << " <logging_level> [storage_dir]" << std::endl;
		std::cerr << "Logging levels: 1 - Critical, 2 - Error, 3 - Warning, 4 - Info, 5 - Verbose" << std::endl;
		return 1;
	}

	uint32_t activityLevel = (argc == 2) ? static_cast<uint32_t>(std::atoi(argv[1])) : 4;
	fs::path storageRoot = (argc == 3) ? fs::path(argv[2]) : fs::current_path();

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

	{
		auto enclaveInterface = VbsEnclave::Trusted::Stubs::SampleEnclave(enclave.get());
		THROW_IF_FAILED(enclaveInterface.RegisterVtl0Callbacks());

		std::vector<uint8_t> mrenclaveHashMaterial;
		THROW_IF_FAILED(enclaveInterface.StoragePocCommon_GetMrenclaveHash(
			static_cast<uint32_t>(veilLog.GetLogLevel()),
			veilLog.GetLogFilePath(),
			mrenclaveHashMaterial));

		std::wcout << L"MRENCLAVE hash material size: " << mrenclaveHashMaterial.size() << std::endl;
	}

	auto paths = BuildDefaultPaths(storageRoot);

	while (true)
	{
		std::cout << "\n*** Storage PoC Menu ***\n";
		std::cout << "1. Setup (one-time): create blob.txt + data.txt\n";
		std::cout << "2. Post-setup: load, process in enclave, re-encrypt and persist\n";
		std::cout << "3. Show storage paths\n";
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
				std::wcout << L"Digite o payload inicial para setup: ";
				std::wcin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
				std::wstring input;
				std::getline(std::wcin, input);

				auto payload = ToUtf8Bytes(input);
				THROW_IF_FAILED(storagepoc::host::RunSetupFlow(enclave.get(), paths, payload, veilLog));
				std::wcout << L"Setup finalizado. Arquivos blob.txt e data.txt criados." << std::endl;
			}
			else if (choice == 2)
			{
				THROW_IF_FAILED(storagepoc::host::RunPostSetupProcessFlow(enclave.get(), paths, veilLog));
				std::wcout << L"Pos-setup finalizado. data.txt sobrescrito com novo payload criptografado." << std::endl;
			}
			else if (choice == 3)
			{
				std::wcout << L"blob: " << paths.protectedKeyBlobPath.wstring() << std::endl;
				std::wcout << L"data: " << paths.encryptedDataPath.wstring() << std::endl;
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
