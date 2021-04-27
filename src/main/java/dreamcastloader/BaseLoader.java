/* 
 * Dreamcast/Naomi/Atomiswave ghidra loader
 * Copyright 2021 flyinghead
 * 
 * Based on ghidra_sdc_ldr by Vladimir Kononovich (https://github.com/lab313ru/ghidra_sdc_ldr)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package dreamcastloader;

import java.io.InputStream;

import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public abstract class BaseLoader extends AbstractLibrarySupportLoader {
	protected static final long KB = 1024;
	protected static final long MB = KB * KB;

	protected static void createNamedByte(FlatProgramAPI fpa, long address, String name, String comment, MessageLog log, Namespace ns) {
		Address addr = fpa.toAddr(address);
		
		try {
			fpa.createByte(addr);
		} catch (Exception e) {
			log.appendException(e);
			return;
		}
		
		try {
			fpa.getCurrentProgram().getSymbolTable().createLabel(addr, name, ns, SourceType.IMPORTED);
			fpa.getCurrentProgram().getListing().setComment(addr, CodeUnit.REPEATABLE_COMMENT, comment);
		} catch (InvalidInputException e) {
			log.appendException(e);
		}
	}
	
	protected static void createNamedWord(FlatProgramAPI fpa, long address, String name, String comment, MessageLog log, Namespace ns) {
		Address addr = fpa.toAddr(address);
		
		try {
			fpa.createWord(addr);
		} catch (Exception e) {
			log.appendException(e);
			return;
		}
		
		try {
			fpa.getCurrentProgram().getSymbolTable().createLabel(addr, name, ns, SourceType.IMPORTED);
			fpa.getCurrentProgram().getListing().setComment(addr, CodeUnit.REPEATABLE_COMMENT, comment);
		} catch (InvalidInputException e) {
			log.appendException(e);
		}
	}
	
	protected static void createNamedDword(FlatProgramAPI fpa, long address, String name, String comment, MessageLog log, Namespace ns) {
		Address addr = fpa.toAddr(address);
		
		try {
			fpa.createDWord(addr);
		} catch (Exception e) {
			log.appendException(e);
			return;
		}
		
		try {
			fpa.getCurrentProgram().getSymbolTable().createLabel(addr, name, ns, SourceType.IMPORTED);
			fpa.getCurrentProgram().getListing().setComment(addr, CodeUnit.REPEATABLE_COMMENT, comment);
		} catch (InvalidInputException e) {
			log.appendException(e);
		}
	}
	
	protected static void createNamedDwords(FlatProgramAPI fpa, long address, String name, int count, String comment, MessageLog log, Namespace ns) {
		Address addr = fpa.toAddr(address);
		
		try {
			fpa.createDwords(addr, count);
		} catch (Exception e) {
			log.appendException(e);
			return;
		}
		
		try {
			fpa.getCurrentProgram().getSymbolTable().createLabel(addr, name, ns, SourceType.IMPORTED);
			fpa.getCurrentProgram().getListing().setComment(addr, CodeUnit.REPEATABLE_COMMENT, comment);
		} catch (InvalidInputException e) {
			log.appendException(e);
		}
	}
	
	protected static void createSegment(FlatProgramAPI fpa, InputStream stream, String name, long address, long size, boolean write, boolean execute, MessageLog log) {
		MemoryBlock block;
		try {
			block = fpa.createMemoryBlock(name, fpa.toAddr(address), stream, size, false);
			block.setRead(true);
			block.setWrite(write);
			block.setExecute(execute);
		} catch (Exception e) {
			log.appendException(e);
		}
	}
	
	protected static Namespace createNamespace(FlatProgramAPI fpa, String name, MessageLog log) {
		try {
			return fpa.getCurrentProgram().getSymbolTable().createNameSpace(null, name, SourceType.IMPORTED); 
		} catch (InvalidInputException e) {
			log.appendException(e);
			return null;
		} catch (DuplicateNameException e) {
			log.appendException(e);
			return null;
		}
	}

	protected static void createAicaRegisters(FlatProgramAPI fpa, boolean sh4AddressSpace, MessageLog log) {
		Long base = sh4AddressSpace ? 0xA0700000L : 0x00800000L;
		createSegment(fpa, null, "AICA", base, 0x1000C, true, false, log);
		Namespace ns = createNamespace(fpa, "AICA", log);
		for (int i = 0; i < 64; i++)
			// TODO	
			createNamedWord(fpa, base + i * 0x80, "CH" + i, "Channel " + i + " registers", log, ns);

		createNamedWord(fpa, base + 0x02800L, "VER_MVOL", "Mono Mem-8MB DAC-18bits VER MVOL", log, ns);
		createNamedWord(fpa, base + 0x02804L, "RBL_RBP", "Ring Buffer Length, Ring Buffer Pointer", log, ns);
		createNamedWord(fpa, base + 0x02808L, "MIBUF", "MOFUL MOEMP MIOVF MIFUL MIEMP MIBUF", log, ns);
		createNamedWord(fpa, base + 0x0280CL, "MSLC_MOBUF", "AFSET MSLC MOBUF", log, ns);
		createNamedWord(fpa, base + 0x02810L, "EG", "LP SGC EG", log, ns);
		createNamedWord(fpa, base + 0x02814L, "CA", "Position of the current sample", log, ns);
		createNamedWord(fpa, base + 0x02880L, "DMEAH_MRWINH", "DMEA[22:16] MRWINH", log, ns);
		createNamedWord(fpa, base + 0x02884L, "DMEAL", "DMEA[15:2] DMA wave memory address", log, ns);
		createNamedWord(fpa, base + 0x02888L, "DRGA", "DGATE DRGA", log, ns);
		createNamedWord(fpa, base + 0x0288CL, "DLG", "DDIR DLG DEXE", log, ns);
		createNamedWord(fpa, base + 0x02890L, "TACTL_TIMA", "Timer A control and counter", log, ns);
		createNamedWord(fpa, base + 0x02894L, "TBCTL_TIMB", "Timer B control and counter", log, ns);
		createNamedWord(fpa, base + 0x02898L, "TCCTL_TIMC", "Timer C control and counter", log, ns);
		createNamedWord(fpa, base + 0x0289CL, "SCIEB", "ARM interrupt mask", log, ns);
		createNamedWord(fpa, base + 0x028A0L, "SCIPD", "ARM interrupt status", log, ns);
		createNamedWord(fpa, base + 0x028A4L, "SCIRE", "ARM interrupt reset", log, ns);
		createNamedWord(fpa, base + 0x028A8L, "SCILV0", "ARM IRQ level bit 0", log, ns);
		createNamedWord(fpa, base + 0x028ACL, "SCILV1", "ARM IRQ level bit 1", log, ns);
		createNamedWord(fpa, base + 0x028B0L, "SCILV2", "ARM IRQ level bit 2", log, ns);
		createNamedWord(fpa, base + 0x028B4L, "MCIEB", "SH4 interrupt mask", log, ns);
		createNamedWord(fpa, base + 0x028B8L, "MCIPD", "SH4 interrupt status", log, ns);
		createNamedWord(fpa, base + 0x028BCL, "MCIRE", "SH4 interrupt reset", log, ns);

		if (sh4AddressSpace)
		{
			createNamedWord(fpa, base + 0x02C00L, "ARMRST", "VREG ARMRST", log, ns);

			createNamedWord(fpa, base + 0x10000L, "RTCH", "RTC[31:16] Real time clock", log, ns);
			createNamedWord(fpa, base + 0x10004L, "RTCL", "RTC[15:0] Real time clock", log, ns);
			createNamedWord(fpa, base + 0x10008L, "RTC_EN", "RTC write enable", log, ns);
		}
		else
		{
			createNamedWord(fpa, base + 0x2D00, "INT_LVL", "Interrupt bits", log, ns);
			createNamedWord(fpa, base + 0x2D04, "INT_MASK", "Interrupt mask bits", log, ns);
		}
	}

}
