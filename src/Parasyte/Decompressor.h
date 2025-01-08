#pragma once
#include "FileHandle.h"

namespace ps
{
 struct BDiffState
	{
		bool headerRead;
		bool error;
		bool eof;
		uint8_t padding;
		uint32_t error_code;
		uint32_t features;
		uint32_t checksum;
	};
	struct DBBinaryPatchStream
	{
		uint8_t file[376];
		BDiffState diffState;
		unsigned int archiveChecksum[4];
		unsigned __int64 something;
		unsigned __int8* sourceWindow;
		unsigned __int64 sourceWindowOffset;
		unsigned __int64 sourceWindowSize;
		unsigned __int64 sourceWindowAllocated;
		unsigned __int8* destWindow;
		unsigned __int64 destWindowOffset;
		unsigned __int64 destWindowSize;
		unsigned __int64 destWindowAllocated;
		unsigned __int64 destWindowReadOffset;
		unsigned __int8* patchWindow;
		unsigned __int64 patchWindowOffset;
		unsigned __int64 patchWindowSize;
		unsigned __int64 patchWindowAllocated;
		unsigned __int64 patchWindowOffsetLast;
		unsigned __int64 patchDataOffset;
		unsigned __int64 diffUncompSize;
		DBBinaryPatchStream* prevStream;
		unsigned __int8* baseFastfileLoad;
	};

	// A class to hold a decompressor.
	class Decompressor
	{
	protected:
		// The file handle.
		ps::FileHandle& File;
		// The current compressed buffer.
		std::unique_ptr<uint8_t[]> CompressedBuffer;
		// The current decompressed buffer.
		std::unique_ptr<uint8_t[]> DecompressedBuffer;
		// The current compressed buffer size.
		size_t CompressedBufferSize;
		// The current decompressed buffer size.
		size_t DecompressedBufferSize;
		// The current offset within the decompressed buffer.
		size_t DecompressedBufferOffset;
		// The current decompressor flags.
		size_t Flags;
		// If the current file stream is secure.
		bool Secure;

	public:
		// Creates a new decompressor.
		Decompressor(ps::FileHandle& file, bool secure);

		// Reads decompressed data from the data stream.
		virtual size_t Read(void* ptr, const size_t size, const size_t offset) = 0;
		// Checks if the provided decompressor is valid.
		virtual bool IsValid() const;
	};
}

