/*
 * Phar Lap P3 EXP Loader
 * Copyright (C) 2026 hk47196
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for details.
 */
package p3exp;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.Loader.ImporterSettings;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Loader for Phar Lap P3 format .EXP files.
 *
 * P3 is a flat-model 32-bit protected mode executable format used by
 * Phar Lap DOS extenders (primarily Free386). These files contain a P3
 * header followed by a flat 32-bit code/data image.
 */
public class P3ExpLoader extends AbstractProgramWrapperLoader {

	private static final int P3_HEADER_SIZE = 0x200;
	private static final byte[] P3_SIGNATURE = {'P', '3'};

	@Override
	public String getName() {
		return "Phar Lap P3 Executable (EXP)";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		// Check if file is large enough for P3 header
		if (provider.length() < P3_HEADER_SIZE) {
			return loadSpecs;
		}

		// Check P3 signature
		BinaryReader reader = new BinaryReader(provider, true); // little-endian
		byte[] signature = reader.readByteArray(0, 2);
		if (!Arrays.equals(signature, P3_SIGNATURE)) {
			return loadSpecs;
		}

		// Check model field (offset 0x02) - must be 1 for flat model
		int model = reader.readUnsignedShort(0x02);
		if (model != 1) {
			return loadSpecs;
		}

		// Read load offset to use as image base
		long loadOffset = reader.readUnsignedInt(0x5E);

		// P3 files are 32-bit x86 protected mode executables
		// Offer multiple compiler specs based on common DOS toolchains

		// Option 1: Borland C++ calling convention (PREFERRED)
		// Most common for DOS extender development (Borland C++, Turbo C++)
		// Uses register-based parameter passing (fastcall-like)
		loadSpecs.add(new LoadSpec(this, loadOffset,
			new LanguageCompilerSpecPair("x86:LE:32:default", "borlandcpp"), true));

		// Option 2: Default calling convention
		// Generic option if compiler is unknown
		loadSpecs.add(new LoadSpec(this, loadOffset,
			new LanguageCompilerSpecPair("x86:LE:32:default", "default"), false));

		// Option 3: GCC calling convention
		// For code built with DJGPP or similar GCC-based DOS compilers
		// Uses cdecl (stack-based parameter passing)
		loadSpecs.add(new LoadSpec(this, loadOffset,
			new LanguageCompilerSpecPair("x86:LE:32:default", "gcc"), false));

		// Option 4: Visual Studio / Windows calling convention
		// Less common for pure DOS, but included for completeness
		loadSpecs.add(new LoadSpec(this, loadOffset,
			new LanguageCompilerSpecPair("x86:LE:32:default", "windows"), false));

		return loadSpecs;
	}

	@Override
	protected void load(Program program, ImporterSettings settings)
			throws CancelledException, IOException {

		ByteProvider provider = settings.provider();
		MessageLog log = settings.log();
		TaskMonitor monitor = settings.monitor();

		monitor.setMessage("Parsing P3 header...");
		BinaryReader reader = new BinaryReader(provider, true); // little-endian

		// Parse P3 header
		P3Header header = new P3Header(reader);

		// Validate file size
		long actualFileSize = provider.length();
		if (header.fileSize > 0 && header.fileSize != actualFileSize) {
			log.appendMsg(String.format("Warning: Header file size (0x%X) != actual (0x%X)",
				header.fileSize, actualFileSize));
		}
		
		// Checksum (Not validated algorithm)
		if (header.checksum != 0) {
			log.appendMsg(String.format("Header Checksum: 0x%04X (Verification skipped)", header.checksum));
		}

		// Log header information
		log.appendMsg(String.format("P3 Format: Load offset=0x%08X, Entry=0x%08X",
			header.loadOffset, header.entryPoint));

		if (header.isPacked) {
			log.appendMsg(String.format("Packed format detected: %d bytes -> %d bytes",
				header.imageSize, header.imageSizeUnpacked));
		}

		if (header.loadOffset == 0) {
			log.appendMsg("Zero-based addressing detected (load offset = 0x00000000)");
		}
		
		// Stack Size Calculation
		// Based on flatlink output.c: ESP = offset + image_size + padding + stack + mindata
		long imageSizeActual = header.isPacked ? header.imageSizeUnpacked : header.imageSize;
		long padding = (16 - (imageSizeActual & 15)) & 15;
		long calculatedStackBase = header.loadOffset + imageSizeActual + padding;
		long calculatedStackSize = header.espValue - calculatedStackBase;
		
		log.appendMsg("Stack Calculation:");
		log.appendMsg(String.format("  Image End (Unpacked): 0x%08X", header.loadOffset + imageSizeActual));
		log.appendMsg(String.format("  Padding: %d bytes", padding));
		log.appendMsg(String.format("  Stack Base: 0x%08X", calculatedStackBase));
		log.appendMsg(String.format("  Initial ESP: 0x%08X", header.espValue));
		log.appendMsg(String.format("  Calculated Stack Size: 0x%X (%d bytes)", calculatedStackSize, calculatedStackSize));
		
		if (header.stackSizeProprietary != 0) {
			log.appendMsg(String.format("  Proprietary Stack Size (Offset 0x7C): 0x%X", header.stackSizeProprietary));
			if (header.stackSizeProprietary != calculatedStackSize) {
				log.appendMsg("  Warning: Calculated stack size differs from proprietary field!");
			}
		}

		// Log runtime parameters if present
		if (header.runtimeParams != null) {
			RuntimeParamBlock rtp = header.runtimeParams;
			log.appendMsg("Runtime Parameters (DX block):");
			log.appendMsg(String.format("  Interrupt buffer: %d-%d KB",
				rtp.minIntBufferKB, rtp.maxIntBufferKB));
			log.appendMsg(String.format("  Interrupt stacks: %d x %d KB",
				rtp.numIntStacks, rtp.intStackSizeKB));
			log.appendMsg(String.format("  Privilege level: Ring %d",
				rtp.privilegeFlag == 0 ? 0 : 1));
		}

		// Read image data
		monitor.setMessage("Reading image data...");
		byte[] imageData = reader.readByteArray(header.imageOffset, (int)header.imageSize);

		// Decompress if packed
		if (header.isPacked) {
			monitor.setMessage("Decompressing image...");
			imageData = decompressP3Packed(imageData, (int)header.imageSizeUnpacked);
			log.appendMsg(String.format("Decompressed to %d bytes", imageData.length));
		}

		// Create memory blocks
		monitor.setMessage("Creating memory blocks...");
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		Address baseAddr = space.getAddress(header.loadOffset);

		try {
			// Check if segment info table exists
			if (header.segmentInfoSize > 0 && header.segmentInfoElementSize > 0) {
				// Parse segment info and create separate blocks
				log.appendMsg(String.format("Segment info table: %d segments",
					header.segmentInfoSize / header.segmentInfoElementSize));
				createSegmentedMemoryBlocks(reader, header, imageData, program, space, log, monitor);
			} else {
				// No segment info - create single block with mixed permissions
			// No segment info - create blocks based on flat memory layout
			// Layout: [Image] [Padding] [Stack] [Heap]
			log.appendMsg("No segment info table - reconstructing flat memory layout");

			// 1. Create .flat_image block (Code + Data)
			// P3 flat images contain both code and data, so RWX is appropriate.
			// Ghidra's analysis will follow the entry point.
			InputStream dataStream = new ByteArrayInputStream(imageData);
			MemoryBlock imageBlock = program.getMemory().createInitializedBlock(
				".flat_image",
				baseAddr,
				dataStream,
				imageData.length,
				monitor,
				false
			);
			imageBlock.setRead(true);
			imageBlock.setWrite(true);
			imageBlock.setExecute(true);
			imageBlock.setComment("P3 executable image (code and initialized data)");
			imageBlock.setSourceName("P3 Loader");
			log.appendMsg(String.format("Created .flat_image block at 0x%08X, size 0x%X (RWX)",
				header.loadOffset, imageData.length));

			// 2. Calculate Stack and Heap regions
			// Based on flatlink output.c: 
			//   stack_x = padding + stack
			//   esp = offset + image_size + stack_x
			//   mindata (header) = stack_x + heap_min
			
			imageSizeActual = header.isPacked ? header.imageSizeUnpacked : header.imageSize;
			padding = (16 - (imageSizeActual & 15)) & 15;
			
			long stackBaseAddr = header.loadOffset + imageSizeActual + padding;
			long stackTopAddr = header.espValue; // ESP points to top of stack (grows down)
			calculatedStackSize = stackTopAddr - stackBaseAddr;
			
			// Header mindata value includes stack and padding
			long headerMinData = header.mindata;
			long heapBaseAddr = stackTopAddr;
			long heapSize = 0;
			
			// Calculate actual heap size (header.mindata - (stack + padding))
			// Note: header.mindata is the offset from end of image to end of heap
			long stackAndPadding = calculatedStackSize + padding;
			if (headerMinData > stackAndPadding) {
				heapSize = headerMinData - stackAndPadding;
			}

			log.appendMsg("Memory Layout Calculation:");
			log.appendMsg(String.format("  Image End:   0x%08X", header.loadOffset + imageSizeActual));
			log.appendMsg(String.format("  Padding:     %d bytes", padding));
			log.appendMsg(String.format("  Stack Base:  0x%08X", stackBaseAddr));
			log.appendMsg(String.format("  Stack Top:   0x%08X (ESP)", stackTopAddr));
			log.appendMsg(String.format("  Stack Size:  0x%X (%d bytes)", calculatedStackSize, calculatedStackSize));
			log.appendMsg(String.format("  Heap Base:   0x%08X", heapBaseAddr));
			log.appendMsg(String.format("  Heap Size:   0x%X (%d bytes)", heapSize, heapSize));

			if (header.stackSizeProprietary != 0 && header.stackSizeProprietary != calculatedStackSize) {
				log.appendMsg(String.format("  Warning: Calculated stack size differs from proprietary field (0x%X)", 
					header.stackSizeProprietary));
			}

			// 3. Create .stack block
			if (calculatedStackSize > 0) {
				Address stackAddr = space.getAddress(stackBaseAddr);
				MemoryBlock stackBlock = program.getMemory().createUninitializedBlock(
					".stack",
					stackAddr,
					calculatedStackSize,
					false
				);
				stackBlock.setRead(true);
				stackBlock.setWrite(true);
				stackBlock.setExecute(false); // Stack is usually not executable
				stackBlock.setComment("P3 Stack (Uninitialized)");
				stackBlock.setSourceName("P3 Loader");
				log.appendMsg(String.format("Created .stack block at 0x%08X, size 0x%X (RW-)",
					stackBaseAddr, calculatedStackSize));
			}

			// 4. Create .heap block
			if (heapSize > 0) {
				Address heapAddr = space.getAddress(heapBaseAddr);
				MemoryBlock heapBlock = program.getMemory().createUninitializedBlock(
					".heap",
					heapAddr,
					heapSize,
					false
				);
				heapBlock.setRead(true);
				heapBlock.setWrite(true);
				heapBlock.setExecute(false);
				heapBlock.setComment(String.format("P3 Heap (Uninitialized, mindata=0x%X)", headerMinData));
				heapBlock.setSourceName("P3 Loader");
				log.appendMsg(String.format("Created .heap block at 0x%08X, size 0x%X (RW-)",
					heapBaseAddr, heapSize));
			}
			} // End of else block

		} catch (Exception e) {
			log.appendException(e);
			throw new IOException("Failed to create memory blocks", e);
		}

		// Apply relocations if present
		if (header.relocTableSize > 0) {
			monitor.setMessage("Applying relocations...");
			log.appendMsg(String.format("Relocation table: offset=0x%X, size=0x%X",
				header.relocTableOffset, header.relocTableSize));
			// TODO: Implement relocation processing
			// Note: P3 relocation format is not documented in standard specs and 
			// open-source tools (flatlink/free386) do not use it for relocatable P3s.
			// Relocations are usually applied at link time for flat model.
			log.appendMsg("Warning: Relocation processing not yet implemented (format unknown)");
		}

		// Set entry point
		monitor.setMessage("Setting entry point...");
		Address entryAddr = space.getAddress(header.entryPoint);
		SymbolTable symTable = program.getSymbolTable();

		try {
			symTable.addExternalEntryPoint(entryAddr);
			symTable.createLabel(entryAddr, "entry",
				program.getGlobalNamespace(), SourceType.IMPORTED);
			log.appendMsg(String.format("Entry point: 0x%08X", header.entryPoint));
		} catch (InvalidInputException e) {
			log.appendMsg("Warning: Failed to create entry point symbol: " + e.getMessage());
		}

		// Parse symbol table if present
		if (header.symbolTableSize > 0) {
			monitor.setMessage("Processing symbol table...");
			log.appendMsg(String.format("Symbol table: offset=0x%X, size=0x%X",
				header.symbolTableOffset, header.symbolTableSize));
			// TODO: Implement symbol table processing
			// Note: P3 symbol table format is not documented in standard specs.
			log.appendMsg("Warning: Symbol table processing not yet implemented (format unknown)");
		}

		// Store initial register values and other info as program properties
		program.getOptions(Program.PROGRAM_INFO).setLong("Initial ESP", header.espValue);
		program.getOptions(Program.PROGRAM_INFO).setLong("Initial CS", header.csValue);
		program.getOptions(Program.PROGRAM_INFO).setLong("Initial SS", header.ssValue);
		program.getOptions(Program.PROGRAM_INFO).setLong("Min Heap (mindata)", header.mindata);
		program.getOptions(Program.PROGRAM_INFO).setLong("Max Heap (maxdata)", header.maxdata);

		log.appendMsg(String.format("Initial ESP: 0x%08X", header.espValue));

		monitor.setMessage("P3 load complete");
	}

	/**
	 * Create memory blocks based on segment info table.
	 */
	private void createSegmentedMemoryBlocks(BinaryReader reader, P3Header header,
			byte[] imageData, Program program, AddressSpace space, MessageLog log,
			TaskMonitor monitor) throws Exception {

		int numSegments = (int)(header.segmentInfoSize / header.segmentInfoElementSize);
		List<SegmentInfo> segments = new ArrayList<>();

		// Parse all segments
		for (int i = 0; i < numSegments; i++) {
			int offset = (int)(header.segmentInfoOffset + i * header.segmentInfoElementSize);
			SegmentInfo seg = new SegmentInfo(reader, offset, header.segmentInfoElementSize);
			segments.add(seg);
		}

		// Create memory blocks for each segment
		for (int i = 0; i < segments.size(); i++) {
			SegmentInfo seg = segments.get(i);

			if (seg.length == 0) {
				continue;  // Skip empty segments
			}

			String name = String.format(".seg%d", i);
			if (seg.isCode()) {
				name = ".text";
			} else if (seg.isWritable()) {
				name = ".data";
			} else {
				name = ".rodata";
			}

			Address segAddr = space.getAddress(seg.baseAddress);
			long imageOffset = seg.baseAddress - header.loadOffset;

			MemoryBlock block;
			if (imageOffset >= 0 && imageOffset < imageData.length) {
				// Initialized segment from image
				int dataStart = (int)imageOffset;
				int dataLen = (int)Math.min(seg.length, imageData.length - imageOffset);
				byte[] segData = Arrays.copyOfRange(imageData, dataStart, dataStart + dataLen);

				InputStream dataStream = new ByteArrayInputStream(segData);
				block = program.getMemory().createInitializedBlock(
					name, segAddr, dataStream, segData.length, monitor, false);
			} else {
				// Uninitialized segment (BSS)
				block = program.getMemory().createUninitializedBlock(
					name, segAddr, seg.length, false);
			}

			block.setRead(true);
			block.setWrite(seg.isWritable());
			block.setExecute(seg.isCode());
			block.setComment(String.format("P3 segment %d (type=0x%X, flags=0x%X)",
				i, seg.segmentType, seg.flags));
			block.setSourceName("P3 Loader");

			log.appendMsg(String.format("  %s: 0x%08X-0x%08X (0x%X bytes) %s%s",
				name, seg.baseAddress, seg.baseAddress + seg.length, seg.length,
				seg.isCode() ? "X" : "-",
				seg.isWritable() ? "W" : "-"));
		}
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram, boolean mirrorFsLayout) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram,
				mirrorFsLayout);

		// P3 loader doesn't need custom options currently
		// Future: Could add options for handling relocations, symbol tables, etc.

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec,
			List<Option> options, Program program) {
		return super.validateOptions(provider, loadSpec, options, program);
	}

	/**
	 * Represents a parsed P3 header (complete structure).
	 */
	private static class P3Header {
		// Basic header
		int headerSize;
		long fileSize;
		int checksum;

		// Runtime and tables
		long runtimeParamOffset;
		long runtimeParamSize;
		long relocTableOffset;
		long relocTableSize;
		long segmentInfoOffset;
		long segmentInfoSize;
		int segmentInfoElementSize;

		// Load image
		long imageOffset;
		long imageSize;
		long imageSizeUnpacked;

		// Symbol table
		long symbolTableOffset;
		long symbolTableSize;

		// Descriptor tables (usually N/A for Free386)
		long gdtOffset;
		long gdtSize;
		long ldtOffset;
		long ldtSize;
		long idtOffset;
		long idtSize;
		long tssOffset;
		long tssSize;

		// Memory allocation
		long mindata;
		long maxdata;
		long loadOffset;

		// Initial register values
		long espValue;
		int ssValue;
		long entryPoint;
		int csValue;
		int ldtRegister;
		int taskRegister;

		// Flags
		int flags;
		boolean isPacked;
		
		// Undocumented
		long stackSizeProprietary;

		// Runtime parameters (if present)
		RuntimeParamBlock runtimeParams;

		P3Header(BinaryReader reader) throws IOException {
			// Basic header
			int model = reader.readUnsignedShort(0x02);
			if (model != 1) {
				throw new IOException("Only flat model (1) supported, got: " + model);
			}

			headerSize = reader.readUnsignedShort(0x04);
			fileSize = reader.readUnsignedInt(0x06);
			checksum = reader.readUnsignedShort(0x0A);

			// Runtime and tables
			runtimeParamOffset = reader.readUnsignedInt(0x0C);
			runtimeParamSize = reader.readUnsignedInt(0x10);
			relocTableOffset = reader.readUnsignedInt(0x14);
			relocTableSize = reader.readUnsignedInt(0x18);
			segmentInfoOffset = reader.readUnsignedInt(0x1C);
			segmentInfoSize = reader.readUnsignedInt(0x20);
			segmentInfoElementSize = reader.readUnsignedShort(0x24);

			// Load image
			imageOffset = reader.readUnsignedInt(0x26);
			imageSize = reader.readUnsignedInt(0x2A);

			// Symbol and descriptor tables
			symbolTableOffset = reader.readUnsignedInt(0x2E);
			symbolTableSize = reader.readUnsignedInt(0x32);
			gdtOffset = reader.readUnsignedInt(0x36);
			gdtSize = reader.readUnsignedInt(0x3A);
			ldtOffset = reader.readUnsignedInt(0x3E);
			ldtSize = reader.readUnsignedInt(0x42);
			idtOffset = reader.readUnsignedInt(0x46);
			idtSize = reader.readUnsignedInt(0x4A);
			tssOffset = reader.readUnsignedInt(0x4E);
			tssSize = reader.readUnsignedInt(0x52);

			// Memory allocation
			mindata = reader.readUnsignedInt(0x56);
			maxdata = reader.readUnsignedInt(0x5A);
			loadOffset = reader.readUnsignedInt(0x5E);

			// Initial register values
			espValue = reader.readUnsignedInt(0x62);
			ssValue = reader.readUnsignedShort(0x66);
			entryPoint = reader.readUnsignedInt(0x68);
			csValue = reader.readUnsignedShort(0x6C);
			ldtRegister = reader.readUnsignedShort(0x6E);
			taskRegister = reader.readUnsignedShort(0x70);

			// Packed format detection
			flags = reader.readUnsignedShort(0x72);
			imageSizeUnpacked = reader.readUnsignedInt(0x74);
			isPacked = (flags & 0x01) != 0 || imageSize != imageSizeUnpacked;
			
			// Undocumented/Proprietary fields
			stackSizeProprietary = reader.readUnsignedInt(0x7C);

			// Parse runtime parameter block if present
			if (runtimeParamOffset > 0 && runtimeParamSize >= 0x18) {
				try {
					byte[] sig = reader.readByteArray((int)runtimeParamOffset, 2);
					if (sig[0] == 'D' && sig[1] == 'X') {
						runtimeParams = new RuntimeParamBlock(reader, (int)runtimeParamOffset);
					}
				} catch (Exception e) {
					// Runtime params not readable, skip
					runtimeParams = null;
				}
			}
		}
	}

	/**
	 * Runtime Parameter Block (DX signature) for Free386.
	 */
	private static class RuntimeParamBlock {
		int minRealmodeParams;
		int maxRealmodeParams;
		int minIntBufferKB;
		int maxIntBufferKB;
		int numIntStacks;
		int intStackSizeKB;
		int realmodeCodeEnd;
		int callBufferKB;
		int runtimeFlags;
		int privilegeFlag;

		RuntimeParamBlock(BinaryReader reader, int offset) throws IOException {
			minRealmodeParams = reader.readUnsignedShort(offset + 0x02);
			maxRealmodeParams = reader.readUnsignedShort(offset + 0x04);
			minIntBufferKB = reader.readUnsignedShort(offset + 0x06);
			maxIntBufferKB = reader.readUnsignedShort(offset + 0x08);
			numIntStacks = reader.readUnsignedShort(offset + 0x0A);
			intStackSizeKB = reader.readUnsignedShort(offset + 0x0C);
			realmodeCodeEnd = reader.readUnsignedShort(offset + 0x0E);
			callBufferKB = reader.readUnsignedShort(offset + 0x12);
			runtimeFlags = reader.readUnsignedShort(offset + 0x14);
			privilegeFlag = reader.readUnsignedShort(offset + 0x16);
		}
	}

	/**
	 * Segment information entry.
	 */
	private static class SegmentInfo {
		int segmentType;  // Type of segment (code, data, BSS, etc.)
		long baseAddress;
		long length;
		int flags;

		SegmentInfo(BinaryReader reader, int offset, int elementSize) throws IOException {
			// Note: Actual segment info structure may vary
			// This is a basic implementation - adjust based on actual P3 spec
			if (elementSize >= 16) {
				segmentType = reader.readUnsignedShort(offset);
				flags = reader.readUnsignedShort(offset + 2);
				baseAddress = reader.readUnsignedInt(offset + 4);
				length = reader.readUnsignedInt(offset + 8);
			}
		}

		boolean isCode() {
			return (flags & 0x04) != 0;  // Executable flag
		}

		boolean isWritable() {
			return (flags & 0x02) != 0;  // Writable flag
		}
	}

	/**
	 * Decompress P3 packed format.
	 * Based on Free386 exp_un_pack_fread algorithm.
	 *
	 * Algorithm:
	 * while (not end):
	 *     C = read 2 bytes (little-endian)
	 *     if (C & 0x8000):  // Bit 15 set = packed
	 *         C = C & 0x7FFF
	 *         L = read 1 byte
	 *         if (L == 0):
	 *             write C bytes of 0x00
	 *         else:
	 *             STR = read L bytes
	 *             write STR, C bytes total (repeat pattern)
	 *     else:  // Not packed
	 *         write next C bytes directly
	 */
	private byte[] decompressP3Packed(byte[] packed, int unpackedSize) throws IOException {
		byte[] result = new byte[unpackedSize];
		int srcPos = 0;
		int dstPos = 0;

		while (srcPos < packed.length && dstPos < unpackedSize) {
			// Read 2-byte count (little-endian)
			if (srcPos + 2 > packed.length) {
				break;
			}
			int count = (packed[srcPos] & 0xFF) | ((packed[srcPos + 1] & 0xFF) << 8);
			srcPos += 2;

			if ((count & 0x8000) != 0) {  // Bit 15 set - packed data
				count = count & 0x7FFF;

				// Read 1-byte length
				if (srcPos >= packed.length) {
					break;
				}
				int length = packed[srcPos] & 0xFF;
				srcPos++;

				if (length == 0) {
					// Zero fill
					int bytesToWrite = Math.min(count, unpackedSize - dstPos);
					Arrays.fill(result, dstPos, dstPos + bytesToWrite, (byte)0);
					dstPos += bytesToWrite;
				} else {
					// Read pattern and repeat
					if (srcPos + length > packed.length) {
						break;
					}
					byte[] pattern = Arrays.copyOfRange(packed, srcPos, srcPos + length);
					srcPos += length;

					// Write pattern for count bytes (not count repetitions!)
					int bytesWritten = 0;
					while (bytesWritten < count && dstPos < unpackedSize) {
						int bytesToCopy = Math.min(length,
							Math.min(count - bytesWritten, unpackedSize - dstPos));
						System.arraycopy(pattern, 0, result, dstPos, bytesToCopy);
						dstPos += bytesToCopy;
						bytesWritten += length;
					}
				}
			} else {  // Not packed - direct copy
				if (count == 0) {
					break;
				}
				int bytesToCopy = Math.min(count,
					Math.min(packed.length - srcPos, unpackedSize - dstPos));
				System.arraycopy(packed, srcPos, result, dstPos, bytesToCopy);
				srcPos += bytesToCopy;
				dstPos += bytesToCopy;
			}
		}

		return result;
	}
}
