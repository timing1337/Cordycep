#include "pch.h"
#if _WIN64
#include "Parasyte.h"
#include "CoDBO6Handler.h"
#include "OodleDecompressorV4.h"

#include <nlohmann/json.hpp>
using json = nlohmann::ordered_json;

#include <unordered_set>

namespace ps::CoDBO6Internal
{
	// The fast file decompressor.
	std::unique_ptr<Decompressor> FFDecompressor;
	// The patch file decompressor.
	std::unique_ptr<Decompressor> FPDecompressor;

	// Initializes the patch function info.
	uint64_t(__fastcall* InitializePatch)();
	// Loads from the data stream.
	bool (__fastcall* LoadStream)(uint8_t* a1, uint64_t* a2, uint64_t* a3);
	// Function that handles requesting and resolving patch data
	uint64_t(__cdecl* RequestPatchedData)(DBBinaryPatchStream* stream, BDiffState* state, void* c, void* d, void* e);
	// Decrypts a string.
	char* (__cdecl* DecryptString)(void* a, size_t b, char* c, char* result);
	// Parses a fast file and all data within it.
	void* (__cdecl* Load_ArchiveData)(const void* a, const char* b, const char* c, bool d);
	// Assigns fast file memory pointers.
	void(__cdecl* DB_InitStreams)(void* blocks);
	// Adds an asset offset to the list.
	void(__cdecl* AddAssetOffset)(size_t* assetType);
	// Gets the xasset name.
	const char* (__fastcall* GetXAssetName)(uint32_t xassetType, void* xassetHeader);
	// Gets the xasset type name.
	const char* (__fastcall* GetXAssetTypeName)(uint32_t xassetType);
	// Gets the xasset header size.
	uint32_t(__fastcall* GetXAssetHeaderSize)(uint32_t xassetType);
	// Checks if the xasset type has a name value.
	const char* (__fastcall* XAssetTypeHasName)(uint32_t xassetType);
	// Initializes Asset Alignment.
	void(__cdecl* DB_PatchMem_BeginLoad)();
	// Hash asset name
	char* (__cdecl* HashAssetName)(char* assetName);



	// Zone Loader Flag (must be 1)
	uint8_t* ZoneLoaderFlag = nullptr;
	// LoadStream function pointers
	uint64_t** LoadStreamFuncPointers = nullptr;
	// The size of the below buffer
	size_t XAssetAlignmentBufferSize = 65535 * 32;
	// A list of offsets for each buffer
	uint64_t* XAssetOffsetList = nullptr;
	// A buffer for asset alignment.
	std::unique_ptr<uint8_t[]> XAssetAlignmentBuffer = nullptr;
	// A buffer for patch file.
	std::unique_ptr<DBBinaryPatchStream> PatchFileState = nullptr;
	// A buffer for loading strings.
	std::unique_ptr<uint8_t[]> StrDecryptBuffer = nullptr;
	// The size of the above string buffer.
	constexpr size_t StrDecryptBufferSize = 65535;
	// Current string offset being allocated.
	uint32_t StrBufferOffset = 0;
	// asset type name -> asset type mapping
	std::map<std::string, uint32_t> AssetTypeMapping;
	// offset -> stream address
	std::map<uint64_t, uint8_t*> StreamOffsetsList;

	//Horray! In Black Ops 6: They changed how do they resolve stream (to deal with asset duplication)
	//now they are supposedly saved in a buffer to be referenced/used later by other asset
	//This is a quick workaround to it
	//Please don't patch them :(
	uint8_t* ResolveStreamPosition(uint64_t offset, uint8_t* ptr) {
		offset &= 0x1FFFFFFFFFFFFFFF; //de "hash" the offset
		
		if (StreamOffsetsList.find(offset) == StreamOffsetsList.end()) {
			// This doesn't need an exception. Just a reminder for me to deal with it later :P
			// Save a log
			ps::log::Log(ps::LogType::Error, "Can't find the address mentioned. Offset: %llx", offset);
			return 0;
		}
		*(uint8_t**)ptr = StreamOffsetsList[offset];
		return StreamOffsetsList[offset];
	}

	uint8_t* RegisterStream(uint64_t offset, uint8_t* ptr) {
		offset &= 0x1FFFFFFFFFFFFFFF; //de "hash" the offset
		if (StreamOffsetsList.find(offset) != StreamOffsetsList.end()) {
			auto resolvedValue = StreamOffsetsList[offset];
			ps::log::Log(ps::LogType::Error, "Offset is already register. Overriding. Offset: %llx, old: %llx, new %llx", offset, resolvedValue, (uint64_t)ptr);
		}
		StreamOffsetsList[offset] = ptr;
		ps::log::Log(ps::LogType::Verbose, "Registered offset: %llx, Address: %llx", offset, (uint64_t)ptr);
		return ptr;
	}

	// Loads from the data stream.
	bool LoadStreamNew(void* doesntSeemUsedlmao, uint8_t** a1, uint64_t** a2, uint64_t** a3)
	{
		return LoadStream(*a1, *a2, *a3);
	}

	uint8_t* DB_BinaryPatch_LoadSourceData(DBBinaryPatchStream* stream, uint64_t offset, uint64_t size)
	{
		uint64_t sourceWindowSize = stream->sourceWindowSize;
		uint64_t sourceWindowOffset = stream->sourceWindowOffset;
		if (offset + size <= sourceWindowOffset + sourceWindowSize)
		{
			return &stream->sourceWindow[offset - sourceWindowOffset];
		}

		uint64_t v10 = 0;
		if (offset != sourceWindowOffset)
		{
			if (offset >= sourceWindowSize + sourceWindowOffset)
			{
				v10 = offset - sourceWindowSize - sourceWindowOffset;
				sourceWindowSize = 0;
			}
			else
			{
				sourceWindowSize -= offset - sourceWindowOffset;
				std::memcpy(stream->sourceWindow, &stream->sourceWindow[offset - sourceWindowOffset], sourceWindowSize);
			}
			stream->sourceWindowOffset = offset;
		}

		if (v10 != 0) {
			//and the crowd feels....stupid?
			auto temp = malloc(v10);
			FFDecompressor->Read(temp, v10, 0);
			free(temp);
		}

		stream->sourceWindowSize = size;
		auto v12 = size - sourceWindowSize;
		if (v12 > 0)
		{
			FFDecompressor->Read(&stream->sourceWindow[sourceWindowSize], v12, 0);
		}
		return stream->sourceWindow;
	}

	uint8_t* DB_BinaryPatch_LoadPatchData(DBBinaryPatchStream* stream, uint64_t offset, uint64_t size, uint64_t* pOffset)
	{
		if (offset != 0)
			stream->patchWindowOffsetLast = offset;
		else
			offset = stream->patchWindowOffsetLast;
		if (pOffset != 0)
			*pOffset = offset;
		uint64_t patchWindowSize = stream->patchWindowSize;
		uint64_t patchWindowOffset = stream->patchWindowOffset;
		if (offset + size <= patchWindowOffset + patchWindowSize)
			return &stream->patchWindow[offset - patchWindowOffset];

		uint64_t v12 = 0;
		if (offset != patchWindowOffset)
		{
			if (offset >= patchWindowSize + patchWindowOffset)
			{
				v12 = offset - patchWindowSize - patchWindowOffset;
				patchWindowSize = 0;
			}
			else
			{
				patchWindowSize -= offset - patchWindowOffset;
				std::memcpy(stream->patchWindow, &stream->patchWindow[offset - patchWindowOffset], patchWindowSize);
			}
			stream->patchWindowOffset = offset;
		}

		if (size > 0 && patchWindowSize < size)
		{
			uint64_t v9 = stream->diffUncompSize - patchWindowSize - offset;
			if (v9 > 0)
			{
				if (size - patchWindowSize <= v9)
					v9 = size - patchWindowSize;
				FPDecompressor->Read(&stream->patchWindow[patchWindowSize], v9, 0);
				patchWindowSize += v9;
				stream->patchDataOffset += v9;
			}
			stream->patchWindowSize = patchWindowSize;
			if (patchWindowSize == 0)
				return 0;
		}
		else
		{
			stream->patchWindowSize = patchWindowSize;
		}

		return stream->patchWindow;
	}

	uint8_t* DB_BinaryPatch_SetupDestData(DBBinaryPatchStream* stream, uint64_t size)
	{
		stream->destWindowSize = size;
		return stream->destWindow;
	}
	// Reads data from the Fast File. If patching is enabled, then data is consumed from the patch and fast file.
	void ReadXFile(char* pos, size_t size)
	{
		// We have a patch file included
		if (FPDecompressor->IsValid() && PatchFileState != nullptr && PatchFileState.get()->diffUncompSize > 0)
		{
			DBBinaryPatchStream* patch = PatchFileState.get();
			size_t remaining = size;

			while (remaining > 0)
			{
				// We need to check if we need more data from the patch/fast file.
				if (patch->destWindowSize == patch->destWindowReadOffset)
				{
					patch->destWindowReadOffset = 0;

					if (!RequestPatchedData(
						PatchFileState.get(),
						&PatchFileState.get()->diffState,
						DB_BinaryPatch_LoadSourceData,
						DB_BinaryPatch_LoadPatchData,
						DB_BinaryPatch_SetupDestData))
					{
						ps::log::Log(ps::LogType::Error, "Failed to patch fast file, error code: %lli", *(uint32_t*)(PatchFileState.get() + 380));
						throw std::exception("MW6_PatchFile_RequestData(...) failed");
					}
				}

				size_t size = patch->destWindowSize - patch->destWindowReadOffset;

				if (remaining < size)
					size = remaining;

				std::memcpy(pos, &patch->destWindow[patch->destWindowReadOffset], size);
				patch->destWindowReadOffset += size;
				pos += size;
				remaining -= size;
			}
		}
		else
		{
			FFDecompressor->Read(pos, size, 0);
		}
	}

	// Resets patch file structure.
	void ResetPatchState(size_t headerDataSize, size_t headerFastFileDataSize, size_t headerPatchFileDataSize, size_t headerDecompressedSize)
	{
		// Check if we need to initialize the data buffer
		if (PatchFileState == nullptr && headerDataSize != 0 && headerFastFileDataSize != 0 && headerPatchFileDataSize != 0)
			PatchFileState = std::make_unique<DBBinaryPatchStream>();

		if (PatchFileState != nullptr)
		{
			//TODO: create another seperate function
			//for freeing source windows and patch windows
			if (PatchFileState.get()->sourceWindow != nullptr)
				_aligned_free(PatchFileState.get()->sourceWindow);
			if (PatchFileState.get()->destWindow != nullptr)
				_aligned_free(PatchFileState.get()->destWindow);
			if (PatchFileState.get()->patchWindow != nullptr)
				_aligned_free(PatchFileState.get()->patchWindow);

			PatchFileState.get()->sourceWindow = nullptr;
			PatchFileState.get()->destWindow = nullptr;
			PatchFileState.get()->patchWindow = nullptr;
		}

		// If we're passing 0, we're not allocating, just freeing.
		if (headerDataSize != 0 && headerFastFileDataSize != 0 && headerPatchFileDataSize != 0)
		{
			std::memset(PatchFileState.get(), 0, sizeof(DBBinaryPatchStream));

			// Align our data sizes
			size_t dataSize = (headerDataSize + 4095) & 0xFFFFFFFFFFFFF000;
			if (dataSize < 0x10000)
				dataSize = 0x10000;
			size_t fastFileDataSize = (headerFastFileDataSize + 4095) & 0xFFFFFFFFFFFFF000;
			if (fastFileDataSize < 0x10000)
				fastFileDataSize = 0x10000;
			size_t patchFileDataSize = (headerPatchFileDataSize + 4095) & 0xFFFFFFFFFFFFF000;
			if (patchFileDataSize < 0x10000)
				patchFileDataSize = 0x10000;

			PatchFileState.get()->destWindow = (uint8_t*)_aligned_malloc(dataSize, 4096);
			PatchFileState.get()->sourceWindow = (uint8_t*)_aligned_malloc(fastFileDataSize, 4096);
			PatchFileState.get()->patchWindow = (uint8_t*)_aligned_malloc(patchFileDataSize, 4096);
		}

		if(PatchFileState != nullptr)
			PatchFileState.get()->diffUncompSize = headerDecompressedSize;
		
	}
	// Allocates a unique string entry.
	void* AllocateUniqueString(char* a, char* str, int type)
	{
		// std::ofstream out("chunky.csv", std::ios::app);

		char* decrypted = str;

		// Check if the string is actually encrypted.
		if ((*str & 0xC0) == 0x80) {
			decrypted = DecryptString(StrDecryptBuffer.get(), StrDecryptBufferSize, str, nullptr);
		}

		auto strLen = strlen(decrypted) + 1;
		auto id = XXHash64::hash(decrypted, strLen, 0);
		auto potentialEntry = ps::Parasyte::GetCurrentHandler()->StringLookupTable->find(id);

		if (potentialEntry != ps::Parasyte::GetCurrentHandler()->StringLookupTable->end())
		{
			StrBufferOffset = (uint32_t)potentialEntry->second;
			return &StrBufferOffset;
		}

		auto offset = ps::Parasyte::GetCurrentHandler()->StringPoolSize;
		std::memcpy(&ps::Parasyte::GetCurrentHandler()->Strings[offset], decrypted, strLen);

		ps::Parasyte::GetCurrentHandler()->StringPoolSize += strLen;
		ps::Parasyte::GetCurrentHandler()->StringLookupTable->operator[](id) = offset;

		StrBufferOffset = (uint32_t)offset;

		return &StrBufferOffset;
	}

	void memfill(char* pointer, uint8_t value, uint64_t size)
	{
		DWORD d;
		VirtualProtect((LPVOID)pointer, sizeof(uint8_t), PAGE_EXECUTE_READWRITE, &d);
		for (uint64_t i = 0; i < size; i++) {
			*(uint8_t*)(pointer + i) = value;
		}
		VirtualProtect((LPVOID)pointer, sizeof(uint8_t), d, &d);
		FlushInstructionCache(GetCurrentProcess(), (LPVOID)pointer, sizeof(uint8_t));
	}

	// Initializes Asset Alignment.
	void InitAssetAlignment()
	{
		// Seems to store offsets to assets and some value used for alignment
		// seems to tie into their patching system so they can keep relative
		// pointers the same?

		std::memset(XAssetAlignmentBuffer.get(), 0, XAssetAlignmentBufferSize);

		for (size_t i = 0; i < 16; i++)
		{
			if (XAssetOffsetList[i] > 0)
			{
				XAssetOffsetList[i] = (uint64_t)(XAssetAlignmentBuffer.get() + 65535 * i);
			}
		}
	}

	void* LinkGenericXAsset(const uint32_t assetType, uint8_t* asset) {
		auto hash = (uint64_t)GetXAssetName(assetType, asset);
		hash &= 0x7FFFFFFFFFFFFFFF;
		auto temp = hash & 0x8000000000000000;
		auto pool = &ps::Parasyte::GetCurrentHandler()->XAssetPools[assetType];
		auto assetTypeName = GetXAssetTypeName(assetType);
		auto size = GetXAssetHeaderSize(assetType);

		// TODO: Make a hash version of LinkXAssetEntry()
		auto result = pool->FindXAssetEntry(hash, assetType);

		// We need to check if we have an existing asset to override
		// If we have, we need to override or append, maintaining same pointer
		// to the address of the header so that if we unload this ff, etc.
		// the pointers from other assets are maintained
		if (result != nullptr)
		{
			if (temp) {
				result->AppendChild(
					ps::Parasyte::GetCurrentFastFile(),
					(uint8_t*)asset,
					temp);
			}
			else {
				ps::log::Log(ps::LogType::Verbose, "Asset already exists, overwriting: 0x%llx", hash);
				result->Override(
					ps::Parasyte::GetCurrentFastFile(),
					(uint8_t*)asset,
					temp);
			}
		}
		else {
			result = pool->CreateEntry(
				hash,
				assetType,
				size,
				ps::Parasyte::GetCurrentFastFile(),
				(uint8_t*)asset,
				0);
		}

		std::string assetTypeNameStr(assetTypeName);

		// If we're an image, we need to check if we want to allocate an image slot
		if (strcmp(assetTypeName, "image") == 0)
		{
			// Get the image data offsets
			constexpr size_t imageDataPtrOffset = 0x38;
			constexpr size_t imageDataSizeOffset = 0x18;

			const auto gfxImage = result->Header;

			if (*(uint64_t*)(gfxImage + imageDataPtrOffset) != 0 && result->ExtendedData == nullptr)
			{
				const auto imageData = *(uint8_t**)(gfxImage + imageDataPtrOffset);
				const auto imageDataSize = (size_t) * (uint32_t*)(gfxImage + imageDataSizeOffset);

				result->ExtendedDataSize = imageDataSize;
				result->ExtendedData = std::make_unique<uint8_t[]>(result->ExtendedDataSize);
				result->ExtendedDataPtrOffset = imageDataPtrOffset;
				std::memcpy(result->ExtendedData.get(), imageData, result->ExtendedDataSize);
				*(uint64_t*)(gfxImage + imageDataPtrOffset) = (uint64_t)result->ExtendedData.get();

				ps::log::Log(ps::LogType::Verbose, "Resolved loaded data for image, Hash: 0x%llx, Type: 0x%llx", hash, (uint64_t)assetType);
			}
		}

		//deal with localization
		if ((strcmp(assetTypeName, "localize") == 0 || strcmp(assetTypeName, "localizeassetentrydev") == 0) && DecryptString != nullptr)
		{
			uint64_t hash = *(uint64_t*)(result->Header);
			uint8_t* str = *(uint8_t**)(result->Header + 8);
			if ((*str & 0xC0) == 0x80)
			{
				char* decoded = DecryptString(ps::CoDBO6Internal::StrDecryptBuffer.get(), ps::CoDBO6Internal::StrDecryptBufferSize, (char*)str, nullptr);
				ps::log::Log(ps::LogType::Verbose, "Localization entry:%s, Hash:0x%llx", decoded, hash);
				memcpy(*(char**)(result->Header + 8), decoded, strlen(decoded) + 1);
			}
		}
		ps::log::Log(ps::LogType::Verbose, "Linked: 0x%llx Type: 0x%llx (%s) Temp: %d @ 0x%llx", hash, (uint64_t)assetType, GetXAssetTypeName(assetType), temp, (uint64_t)result->Header);
		size_t toPop[2]{ assetType, (size_t)asset };
		AddAssetOffset(toPop);
		return result->Header;

	}
	// Links a generic xasset.
	void* DB_AddXAsset(uint32_t assetType, uint8_t** assetPtr)
	{
		return LinkGenericXAsset(assetType, *assetPtr);
	}

	void* DB_AddXAssetEx(uint32_t assetType, uint64_t hash, char* name) {
		auto temp = hash & 0x8000000000000000;
		hash &= 0x7FFFFFFFFFFFFFFF;
		auto pool = &ps::Parasyte::GetCurrentHandler()->XAssetPools[assetType];
		auto result = pool->FindXAssetEntry(hash, assetType);
		if (result == nullptr) { //oh noes
			ps::log::Log(ps::LogType::Error, "This is extremely bad. Failed to find asset: 0x%llx (type: %s)", hash, GetXAssetTypeName(assetType));
			return 0;
		}
		return result->Header;
	}

	// yer boio
	void __fastcall FixUpXModelSurfsPtr(uint8_t* xmodel)
	{
		// Get the lods data offset
		size_t lodCount = *(uint8_t*)(xmodel + 18);
		uint8_t* lods = *(uint8_t**)(xmodel + 152);
		for (size_t i = 0; i < lodCount; i++)
		{
			uint8_t* xmodelLod = lods + i * 72;
			uint8_t* xmodelSurfs = *(uint8_t**)xmodelLod;

			if (xmodelSurfs != nullptr)
			{
				*(uint64_t*)(xmodelLod + 8) = *(uint64_t*)(xmodelSurfs + 8);
			}
		}
	}

	uint64_t HashAsset(const char* data)
	{
		uint64_t result = 0x47F5817A5EF961BA;

		for (size_t i = 0; i < strlen(data); i++)
		{
			uint64_t value = tolower(data[i]);

			if (value == '\\')
				value = '/';

			result = 0x100000001B3 * (value ^ result);
		}

		return result & 0x7FFFFFFFFFFFFFFF;
	}
}

const std::string ps::CoDBO6Handler::GetName()
{
	return "Call of Duty: Black Ops 6 (2024)";
}

bool ps::CoDBO6Handler::Initialize(const std::string& gameDirectory)
{
	Configs.clear();
	GameDirectory = gameDirectory;

	if (!LoadConfigs("CoDBO6Handler"))
	{
		return false;
	}

	SetConfig();
	CopyDependencies();
	OpenGameDirectory(GameDirectory);
	OpenGameModule(CurrentConfig->ModuleName);

	if (!ps::oodle::Initialize("Data\\Deps\\oo2core_8_win64.dll"))
	{
		ps::log::Log(ps::LogType::Error, "Failed to load the dll for Oodle Decompression.");
		return false;
	}

	Module.LoadCache(CurrentConfig->CacheName);

	ResolvePatterns();

	Variables["ps::CoDBO6Internal::GetXAssetHeaderSize"] = (char*)Module.Handle + 0x276B8C0;
	Variables["ps::CoDBO6Internal::XAssetTypeHasName"] = (char*)Module.Handle + 0x276B8E0;
	Variables["ps::CoDBO6Internal::GetXAssetName"] = (char*)Module.Handle + 0x276B860;
	Variables["ps::CoDBO6Internal::GetXAssetTypeName"] = (char*)Module.Handle + 0x5604700;

	Variables["ps::CoDBO6Internal::DB_PatchMem_BeginLoad"] = (char*)Module.Handle + 0x2778FC0;
	Variables["ps::CoDBO6Internal::DB_InitStreams"] = (char*)Module.Handle + 0x2786E20;
	Variables["ps::CoDBO6Internal::LoadStream"] = (char*)Module.Handle + 0x27C0FB0;
	Variables["ps::CoDBO6Internal::LoadStreamNew"] = (char*)Module.Handle + 0x264DE70;

	Variables["ps::CoDBO6Internal::Load_ArchiveData"] = (char*)Module.Handle + 0x27C0CE0;

	Variables["ps::CoDBO6Internal::ReadXFile"] = (char*)Module.Handle + 0x2773C20;
	Variables["ps::CoDBO6Internal::streamGlobalBlob"] = (char*)Module.Handle + 0xDAD58D8;

	Variables["ps::CoDBO6Internal::RequestPatchedData"] = (char*)Module.Handle + 0x516D9E0;
	Variables["ps::CoDBO6Internal::InitializePatch"] = (char*)Module.Handle + 0x516D410;

	Variables["ps::CoDBO6Internal::DB_AddXAsset"] = (char*)Module.Handle + 0x277D600;
	Variables["ps::CoDBO6Internal::DB_AddXAssetEx"] = (char*)Module.Handle + 0x277FA60;

	Variables["ps::CoDBO6Internal::AddAssetOffset"] = (char*)Module.Handle + 0x2779D10;
	Variables["ps::CoDBO6Internal::XAssetOffsetList"] = (char*)Module.Handle + 0xD7925E0;
	Variables["ps::CoDBO6Internal::ZoneLoaderFlag"] = (char*)Module.Handle + 0xD7925B2;

	Variables["ps::CoDBO6Internal::AllocateUniqueString"] = (char*)Module.Handle + 0x4E6BCA0;
	Variables["ps::CoDBO6Internal::DecryptString"] = (char*)Module.Handle + 0x3AF0D80;

	Variables["ps::CoDBO6Internal::HashAssetName"] = (char*)Module.Handle + 0x20444E0;
	Variables["ps::CoDBO6Internal::ResolveStreamPosition"] = (char*)Module.Handle + 0x27C0930;
	Variables["ps::CoDBO6Internal::RegisterStream"] = (char*)Module.Handle + 0x27C07B0;

	Variables["ps::CoDBO6Internal::memfill"] = (char*)Module.Handle + 0x9039C50;
	
	//Patching evil

	PS_SETGAMEVAR(ps::CoDBO6Internal::GetXAssetHeaderSize);
	PS_SETGAMEVAR(ps::CoDBO6Internal::RequestPatchedData);
	PS_SETGAMEVAR(ps::CoDBO6Internal::DB_InitStreams);
	PS_SETGAMEVAR(ps::CoDBO6Internal::DB_PatchMem_BeginLoad);
	PS_SETGAMEVAR(ps::CoDBO6Internal::InitializePatch);
	PS_SETGAMEVAR(ps::CoDBO6Internal::AddAssetOffset)
	PS_SETGAMEVAR(ps::CoDBO6Internal::XAssetOffsetList);
	PS_SETGAMEVAR(ps::CoDBO6Internal::ZoneLoaderFlag);
	PS_SETGAMEVAR(ps::CoDBO6Internal::Load_ArchiveData);
	PS_SETGAMEVAR(ps::CoDBO6Internal::GetXAssetName);
	PS_SETGAMEVAR(ps::CoDBO6Internal::XAssetTypeHasName);
	PS_SETGAMEVAR(ps::CoDBO6Internal::GetXAssetTypeName);
	PS_SETGAMEVAR(ps::CoDBO6Internal::DecryptString);
	PS_SETGAMEVAR(ps::CoDBO6Internal::LoadStream);
	PS_SETGAMEVAR(ps::CoDBO6Internal::LoadStreamFuncPointers);
	PS_SETGAMEVAR(ps::CoDBO6Internal::HashAssetName);

	PS_DETGAMEVAR(ps::CoDBO6Internal::ReadXFile);
	PS_DETGAMEVAR(ps::CoDBO6Internal::AllocateUniqueString);
	PS_DETGAMEVAR(ps::CoDBO6Internal::DB_AddXAsset);
	PS_DETGAMEVAR(ps::CoDBO6Internal::memfill);
	PS_DETGAMEVAR(ps::CoDBO6Internal::LoadStreamNew);
	PS_DETGAMEVAR(ps::CoDBO6Internal::DB_AddXAssetEx);
	PS_DETGAMEVAR(ps::CoDBO6Internal::RegisterStream);
	PS_DETGAMEVAR(ps::CoDBO6Internal::ResolveStreamPosition);

	Module.Fill((char*)Module.Handle + 0x27C0CFC, 0x90, 7);
	Module.Fill((char*)Module.Handle + 0x277F850, 0xC3, 1);
	Module.Fill((char*)Module.Handle + 0x27C3F00, 0xC3, 1);

	Module.Fill((char*)Module.Handle + 0x27C0D83, 0x90, 1);
	Module.Fill((char*)Module.Handle + 0x27C0D84, 0x31, 1);
	Module.Fill((char*)Module.Handle + 0x27C0D85, 0xC0, 1);


	Module.Fill((char*)Module.Handle + 0x2768890, 0xC3, 1); //dlog
	Module.Fill((char*)Module.Handle + 0x2768830, 0xC3, 1);
	Module.Fill((char*)Module.Handle + 0x2768900, 0xC3, 1); //libshader
	Module.Fill((char*)Module.Handle + 0x27688D0, 0xC3, 1); //Image Extended data
	Module.Fill((char*)Module.Handle + 0x2768AE0, 0xC3, 1); //StreamingInfo
	Module.Fill((char*)Module.Handle + 0x2778B40, 0xC3, 1); //fix xmodel surfs
	Module.Fill((char*)Module.Handle + 0x500C0E0, 0xC3, 1); //soundbanks
	Module.Fill((char*)Module.Handle + 0x345C990, 0xC3, 1); //another variant of stringdecrypt
	Module.Fill((char*)Module.Handle + 0x50A69E0, 0xC3, 1); //another variant of stringdecrypt

	XAssetPoolCount   = 321;
	XAssetPools       = std::make_unique<XAssetPool[]>(XAssetPoolCount);
	Strings           = std::make_unique<char[]>(0x2000000);
	StringPoolSize    = 0;
	Initialized       = true;
	StringLookupTable = std::make_unique<std::map<uint64_t, size_t>>();

	// Game specific buffers.
	ps::CoDBO6Internal::XAssetAlignmentBuffer = std::make_unique<uint8_t[]>((size_t)65535 * 32);
	ps::CoDBO6Internal::StrDecryptBuffer = std::make_unique<uint8_t[]>(ps::CoDBO6Internal::StrDecryptBufferSize);

	Module.SaveCache(CurrentConfig->CacheName);
	LoadAliases(CurrentConfig->AliasesName);

	ps::CoDBO6Internal::InitializePatch();

	for (int i = 0; i < 321; i++) {
		auto assetTypeName = ps::CoDBO6Internal::GetXAssetTypeName(i);
		if (!assetTypeName) break;
		std::string assetTypeNameStr(assetTypeName);
		ps::CoDBO6Internal::AssetTypeMapping[assetTypeNameStr] = i;
		auto size = ps::CoDBO6Internal::GetXAssetHeaderSize(i);
		auto pool = &ps::Parasyte::GetCurrentHandler()->XAssetPools[i];
		pool->Initialize(size, 256);
		ps::log::Log(ps::LogType::Debug, "Registering %s(%d)", assetTypeName, i);
	}
	return true;
}

bool ps::CoDBO6Handler::Deinitialize()
{
	Module.Free();
	XAssetPoolCount        = 321;
	XAssetPools            = nullptr;
	Strings                = nullptr;
	StringPoolSize         = 0;
	Initialized            = false;
	StringLookupTable      = nullptr;
	FileSystem             = nullptr;
	GameDirectory.clear();

	// Clear game specific buffers
	ps::CoDBO6Internal::ResetPatchState(0, 0, 0, 0);
	ps::CoDBO6Internal::PatchFileState = nullptr;
	ps::CoDBO6Internal::XAssetAlignmentBuffer = nullptr;
	ps::CoDBO6Internal::StrDecryptBuffer = nullptr;

	ps::oodle::Clear();

	return true;
}

bool ps::CoDBO6Handler::IsValid(const std::string& param)
{
	return strcmp(param.c_str(), "bo6") == 0;
}

bool DealWithTaff(ps::FileHandle& handle) {
	handle.Read<uint32_t>(); //Magic
	uint32_t count = handle.Read<uint32_t>();
	for (uint32_t i = 0; i < count; i++)
	{
		uint32_t magicConstant = handle.Read<uint32_t>(); //Header
		uint32_t size = handle.Read<uint32_t>(); //Size
		handle.Seek(size, SEEK_CUR);
	}

	uint32_t compressionHeader = handle.Read<uint32_t>();
	if (compressionHeader == 0x46464154 || compressionHeader == 0x46464141 || compressionHeader == 0x41464154 || compressionHeader == 0x54414641)
	{
		handle.Seek(288, SEEK_CUR);
		compressionHeader = handle.Read<uint32_t>();
	}

	// = 0 usually mean no patch file
	if (compressionHeader != 0x43574902 && compressionHeader != 0) {
		throw std::exception("Invalid auth magic number.");
	}
	return true;
}

bool ps::CoDBO6Handler::LoadFastFile(const std::string& ffName, FastFile* parent, BitFlags<FastFileFlags> flags)
{
	ps::log::Log(ps::LogType::Normal, "Attempting to load: %s using handler: %s...", ffName.c_str(), GetName().c_str());

	auto newFastFile = CreateUniqueFastFile(ffName);

	if (newFastFile == nullptr)
	{
		ps::log::Log(ps::LogType::Error, "The file: %s is already loaded.", ffName.c_str());
		return false;
	}

	newFastFile->Parent = parent;
	newFastFile->Flags = flags;

	// Set current ff for loading purposes.
	ps::Parasyte::PushTelemtry("LastFastFileName", ffName);
	ps::Parasyte::SetCurrentFastFile(newFastFile);

	ps::FileHandle ffHandle(FileSystem->OpenFile(GetFileName(ffName + ".ff"), "r"), FileSystem.get());
	ps::FileHandle fpHandle(FileSystem->OpenFile(GetFileName(ffName + ".fp"), "r"), FileSystem.get());

	if (!ffHandle.IsValid())
	{
		ps::log::Log(ps::LogType::Error, "The provided fast file: %s could not be found in the game's file system.", ffName.c_str());
		ps::log::Log(ps::LogType::Error, "Make sure any updates are finished and check for any content packages.");
		UnloadFastFile(ffName);
		return false;
	}

	uint8_t ffHeader[224]{};
	uint8_t fpHeader[504]{};

	ffHandle.Read(&ffHeader[0], 0, sizeof(ffHeader));

	// fucking TAFF bro
	DealWithTaff(ffHandle);

	// We must check if we have a patch file, we'll need to take a different
	// route if we do during file reading to ensure we're patching with new data.
	if (fpHandle.IsValid())
	{
		fpHandle.Read(&fpHeader[0], 0, sizeof(fpHeader));

		if (std::memcmp(&ffHeader[0], &fpHeader[56], sizeof(ffHeader)) != 0)
		{
			ps::log::Log(ps::LogType::Error, "Current fast file header does not match the one within the patch file.");
			ps::log::Log(ps::LogType::Error, "This may indicate your install is corrupt, or the file provided is for content no longer available.");
			return false;
		}
		DealWithTaff(fpHandle);

		// Patch the fast file header
		std::memcpy(&ffHeader[0], &fpHeader[280], sizeof(ffHeader));
	}

	uint64_t* bufferSizes = (uint64_t*)&ffHeader[72];

	for (size_t i = 0; i < 16; i++)
	{
		if (bufferSizes[i] > 0)
		{
			ps::log::Log(ps::LogType::Verbose, "Allocating block: %llu of size: 0x%llx", i, bufferSizes[i]);
			ps::Parasyte::GetCurrentFastFile()->MemoryBlocks[i].Initialize(bufferSizes[i], 4096);
		}
	}

	ps::CoDBO6Internal::ResetPatchState(
		*(uint64_t*)&fpHeader[16],
		*(uint64_t*)&fpHeader[24],
		*(uint64_t*)&fpHeader[32],
		*(uint64_t*)&fpHeader[48]);

	ps::CoDBO6Internal::FFDecompressor = std::make_unique<OodleDecompressorV4>(ffHandle, true);
	ps::CoDBO6Internal::FPDecompressor = std::make_unique<OodleDecompressorV4>(fpHandle, true);

	ps::CoDBO6Internal::InitAssetAlignment();
	ps::CoDBO6Internal::DB_PatchMem_BeginLoad();
	ps::CoDBO6Internal::DB_InitStreams(&ps::Parasyte::GetCurrentFastFile()->MemoryBlocks);
	ps::CoDBO6Internal::ZoneLoaderFlag[0] = 1;
	ps::CoDBO6Internal::Load_ArchiveData(nullptr, ps::Parasyte::GetCurrentFastFile()->AssetList, ffName.c_str(), 0);

	ps::CoDBO6Internal::FFDecompressor = nullptr;
	ps::CoDBO6Internal::FPDecompressor = nullptr;

	// We must fix up any XModel surfs, as we may have overrode previous
	// temporary entries, etc.
	auto xmodelPoolIdx = ps::CoDBO6Internal::AssetTypeMapping["xmodel"];
	ps::Parasyte::GetCurrentHandler()->XAssetPools[xmodelPoolIdx].EnumerateEntries([](ps::XAsset* asset)
	{
		ps::CoDBO6Internal::FixUpXModelSurfsPtr(asset->Header);
	});


	ps::log::Log(ps::LogType::Normal, "Successfully loaded: %s", ffName.c_str());

	// If we have no parent, we are a root, and need to attempt to load the localized, etc.
	if (newFastFile->Parent == nullptr && !flags.HasFlag(FastFileFlags::NoChildren))
	{
		auto techsetsName = "techsets_" + ffName;
		auto wwName = "ww_" + ffName;

		// Attempt to load the techsets file, this usually contains
		// materials, shaders, technique sets, etc.
		if (DoesFastFileExists(techsetsName) && !IsFastFileLoaded(techsetsName))
			LoadFastFile(techsetsName, newFastFile, flags);
		// Attempt to load the ww file, same as locale, not as important
		// but we'll still load it, as it can contain data we need.
		if (DoesFastFileExists(wwName) && !IsFastFileLoaded(wwName))
			LoadFastFile(wwName, newFastFile, flags);

		// Check for locale prefix
		if (!RegionPrefix.empty())
		{
			auto localeName = RegionPrefix + ffName;

			// Now load the locale, not as important, as usually
			// only contains localized data.
			if (DoesFastFileExists(localeName) && !IsFastFileLoaded(localeName))
				LoadFastFile(localeName, newFastFile, flags);
		}
	}

	return true;
}

bool ps::CoDBO6Handler::DumpAliases()
{
	// AssetType: 0x3B
	struct LocalizeEntry
	{
		uint64_t hash;
		char* value;
	};

	// Store localizeEntries as map:(hash - value)
	std::map<size_t, std::string> localizeEntries;
	// Read localizeEntries
	ps::Parasyte::GetCurrentHandler()->XAssetPools[ps::CoDBO6Internal::AssetTypeMapping["localize"]].EnumerateEntries([&](ps::XAsset* asset)
	{
		auto entry = (LocalizeEntry*)asset->Header;
		localizeEntries[entry->hash] = entry->value;
	});

	ps::Parasyte::GetCurrentHandler()->XAssetPools[ps::CoDBO6Internal::AssetTypeMapping["localizeassetentrydev"]].EnumerateEntries([&](ps::XAsset* asset)
	{
		auto entry = (LocalizeEntry*)asset->Header;
		localizeEntries[entry->hash] = entry->value;
	});

	// Read weapon asset data
	uint32_t weaponAssetPoolIdx = ps::CoDBO6Internal::AssetTypeMapping["weapon"];

	json resultJson;
	ps::Parasyte::GetCurrentHandler()->XAssetPools[weaponAssetPoolIdx].EnumerateEntries([&](ps::XAsset* asset)
	{
		const std::string wpnAssetName = ps::CoDBO6Internal::GetXAssetName(weaponAssetPoolIdx, asset->Header);

		json wpnJson;
		std::unordered_set<std::string> xmodelNames;
		std::unordered_set<size_t> xmodelHashes;

		auto header = (size_t)asset->Header;

		auto szInternalNamePtr = header + 8;
		auto szDisplayNamePtr = header + 64;
		auto _attSlotPtr = header + 88;

		auto szInternalName = *(char**)(szInternalNamePtr);
		auto szDisplayName = *(char**)(szDisplayNamePtr);

		for (size_t i = 0; i < 17; ++i) // 17 is not sure, just guess
		{
			auto attSlotPtr = _attSlotPtr + i * 16;

			auto attCount = *(size_t*)attSlotPtr;
			auto _attsPtr = *(size_t*)(attSlotPtr + 8);

			if (!_attsPtr || !attCount)
			{
				continue;
			}

			for (size_t j = 0; j < attCount; ++j)
			{
				auto attsPtr = _attsPtr + j * 8;

				auto att = *(size_t*)attsPtr;

				// Read Base WM
				if (auto baseWmPtrPtr = *(size_t*)(att + 376))
				{
					if (auto baseWmPtr = *(size_t*)baseWmPtrPtr)
					{
						auto wmName = *(char**)(baseWmPtr + 8);
						//ps::log::Print("MAIN", "wm: %s", wmName);
						xmodelNames.insert(wmName);
						xmodelHashes.insert(*(size_t*)baseWmPtr);
					}
				}

				// Read Base VM
				if (auto baseVmPtrPtr = *(size_t*)(att + 384))
				{
					if (auto baseVmPtr = *(size_t*)baseVmPtrPtr)
					{
						auto vmName = *(char**)(baseVmPtr + 8);
						//ps::log::Print("MAIN", "vm: %s", vmName);
						xmodelNames.insert(vmName);
						xmodelHashes.insert(*(size_t*)baseVmPtr);
					}
				}

				auto bpCount = *(uint32_t*)(att + 48);
				auto _bpsPtr = *(size_t*)(att + 56);

				//ps::log::Print("MAIN", "att: %llx", att);
				//ps::log::Print("MAIN", "bpCount: %d", bpCount);
				//ps::log::Print("MAIN", "_bpsPtr: %llx", _bpsPtr);

				if (!bpCount || !_bpsPtr)
				{
					continue;
				}

				for (size_t k = 0; k < bpCount; ++k)
				{
					auto bpsPtr = _bpsPtr + k * 8;
					//ps::log::Print("MAIN", "k: %lld", k);

					auto bp = *(size_t*)bpsPtr;

					if (bp == 0)
					{
						continue;
					}

					auto wmPtr = *(size_t*)(bp + 16);
					auto vmPtr = *(size_t*)(bp + 40);

					if (wmPtr != 0)
					{
						auto wmName = *(char**)(wmPtr + 8);
						//ps::log::Print("MAIN", "wm: %s", wmName);
						xmodelNames.insert(wmName);
						xmodelHashes.insert(*(size_t*)wmPtr);
					}

					if (vmPtr != 0)
					{
						auto vmName = *(char**)(vmPtr + 8);
						//ps::log::Print("MAIN", "vm: %s", vmName);
						xmodelNames.insert(vmName);
						xmodelHashes.insert(*(size_t*)vmPtr);
					}
				}
			}
		}

		std::unordered_set<std::string> ffNames;
		uint32_t xmodelAssetPoolIdx = ps::CoDBO6Internal::AssetTypeMapping["xmodel"];
		auto xmodelPool = &ps::Parasyte::GetCurrentHandler()->XAssetPools[xmodelAssetPoolIdx];
		for (const auto& hash : xmodelHashes)
		{
			auto xmodelAsset = xmodelPool->FindXAssetEntry(hash, xmodelAssetPoolIdx);

			// Failed to find loaded xmodel asset
			if (!xmodelAsset)
			{
				continue;
			}

			const auto& ffName = xmodelAsset->Owner->Name;
			if (xmodelAsset->Temp || ffNames.contains(ffName))
			{
				continue;
			}

			const auto xmodelName = ps::CoDBO6Internal::GetXAssetName((uint32_t)xmodelAssetPoolIdx, xmodelAsset->Header);

			// ps::log::Print("MAIN", "[ff: %s] - [xmodel: %s]", ffName.c_str(), xmodelName);
			ffNames.insert(ffName);
		}

		std::string aliasName = szInternalName ? szInternalName : "*None*";
		if (szDisplayName)
		{
			auto pair = localizeEntries.find(ps::CoDBO6Internal::HashAsset(szDisplayName));
			if (pair != localizeEntries.end())
			{
				aliasName = pair->second;
			}
		}

		wpnJson["alias"] = aliasName;
		wpnJson["name"] = szInternalName;
		wpnJson["fast_files"] = ffNames;

		resultJson.emplace_back(wpnJson);
	});

	std::ofstream out_file(CurrentConfig->AliasesName);
	out_file << resultJson.dump(4);
	out_file.close();

	return true; 
}

bool ps::CoDBO6Handler::CleanUp()
{
	ps::CoDBO6Internal::FFDecompressor = nullptr;
	ps::CoDBO6Internal::FPDecompressor = nullptr;
	ps::CoDBO6Internal::ResetPatchState(0, 0, 0, 0);
	return false;
}

std::string ps::CoDBO6Handler::GetFileName(const std::string& name)
{
	return (CurrentConfig->FilesDirectory.empty()) ? (name) : (CurrentConfig->FilesDirectory + "/" + name);
}

const std::string ps::CoDBO6Handler::GetShorthand()
{
	return "bo6";
}

PS_CINIT(ps::GameHandler, ps::CoDBO6Handler, ps::GameHandler::GetHandlers());
#endif