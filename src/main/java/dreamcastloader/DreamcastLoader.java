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

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader;
import ghidra.framework.model.DomainObject;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.LittleEndianDataConverter;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Sega Dreamcast/Naomi/Atomiswave RAM dump loader
 */
public class DreamcastLoader extends BaseLoader {
	private static final long RAM_SIZE = 16 * MB;
	private static final String RAM_BASE_OPTION = "RAM Base Address";
	private static final String FLAVOR_OPTION = "System Flavor";
	private static final String VBR_OPTION = "VBR";

	private long ramBase = 0x8C000000L;
	private long vbr = 0x8c00f400l;
	enum Flavor {
		Dreamcast,
		Atomiswave,
		Naomi
	}
	private Flavor flavor = Flavor.Dreamcast;

	@Override
	public String getName() {
		return "Dreamcast/Naomi loader";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException
	{
		List<LoadSpec> loadSpecs = new ArrayList<>();

		BinaryReader reader = new BinaryReader(provider, true);
		
		long size = reader.length();
		if (size == RAM_SIZE || size == RAM_SIZE * 2) {
			loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("SuperH4:LE:32:nodouble", "default"), true));
			loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("SuperH4:LE:32:default", "default"), false));
			if (size == RAM_SIZE * 2)
			{
				flavor = Flavor.Naomi;
				vbr = 0x8C000000l;
			}
		}

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException
	{
		FlatProgramAPI fpa = new FlatProgramAPI(program);
		createSegments(fpa, log);
		createSegment(fpa, null, "ROM", 0xA0000000, flavor == Flavor.Atomiswave ? 128 * KB : 2 * MB, false, true, log);
		createSegment(fpa, null, "FLASH", 0xA0200000, 128 * KB, true, false, log);
		createSegment(fpa, null, "AICA_RAM", 0xA0800000, (flavor == Flavor.Dreamcast ? 2 : 8) * MB, true, false, log);
		createSegment(fpa, null, "VRAM64", 0x84000000, (flavor == Flavor.Naomi ? 16 : 8) * MB, true, false, log);
		createSegment(fpa, null, "VRAM32", 0x85000000, (flavor == Flavor.Naomi ? 16 : 8) * MB, true, false, log);
		
		InputStream ramStream = provider.getInputStream(0L);
		createSegment(fpa, ramStream, "RAM", ramBase, flavor == Flavor.Naomi ? RAM_SIZE * 2 : RAM_SIZE, true, true, log);
		
		long entryPoint;
		if (flavor == Flavor.Dreamcast)
			entryPoint = ramBase + 0x8300;
		else if (flavor == Flavor.Naomi)
			entryPoint = ramBase + 0x21000;
		else
			entryPoint = ramBase + 0x10200;
		fpa.addEntryPoint(fpa.toAddr(entryPoint));
		fpa.createFunction(fpa.toAddr(entryPoint), "_entry");
		
		// Interrupt/exception vectors
		long addr = vbr + 0x100;
		fpa.addEntryPoint(fpa.toAddr(addr));
		fpa.createFunction(fpa.toAddr(addr), "_exception_handler");
		addr = vbr + 0x400;
		fpa.addEntryPoint(fpa.toAddr(addr));
		fpa.createFunction(fpa.toAddr(addr), "_tlb_miss_handler");
		addr = vbr + 0x600;
		fpa.addEntryPoint(fpa.toAddr(addr));
		fpa.createFunction(fpa.toAddr(addr), "_interrupt_handler");
		
		if (flavor == Flavor.Dreamcast)
		{
			// BIOS vectors
			createBiosVector(fpa, 0x8C0000B0, "system", provider, log);
			createBiosVector(fpa, 0x8C0000B4, "font", provider, log);
			createBiosVector(fpa, 0x8C0000B8, "flashrom", provider, log);
			createBiosVector(fpa, 0x8C0000BC, "gdrom", provider, log);
			createBiosVector(fpa, 0x8C0000C0, "gdrom2", provider, log);
			createBiosVector(fpa, 0x8C0000E0, "misc", provider, log);
		}
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram)
	{
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		list.add(new SystemFlavorOption(FLAVOR_OPTION, flavor));
		list.add(new RAMBaseOption(RAM_BASE_OPTION, ramBase));
		list.add(new VBROption(Long.toString(vbr, 16)));

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program)
	{
		for (Option option : options) {
			String optName = option.getName();
			if (optName.equals(RAM_BASE_OPTION)) {
				ramBase = Long.decode((String)option.getValue());
			}
			else if (optName.equals(FLAVOR_OPTION)) {
				if (Flavor.Atomiswave.name().equals(option.getValue()))
					flavor = Flavor.Atomiswave;
				else if (Flavor.Naomi.name().equals(option.getValue()))
					flavor = Flavor.Naomi;
				else
					flavor = Flavor.Dreamcast;
			}
			else if (optName.equals(VBR_OPTION)) {
				String v = (String)option.getValue();
				if (v.isEmpty())
				{
					vbr = flavor == Flavor.Naomi ? 0x8C000000l : 0x8c00f400l;
				}
				else
				{
					try {
						vbr = Long.valueOf(v, 16);
					} catch (NumberFormatException e) {
						return e.toString();
					}
				}
			}
		}

		return super.validateOptions(provider, loadSpec, options, program);
	}
	
	class VBROption extends Option {
		public VBROption(Object value) {
			super(VBR_OPTION, value, String.class, Loader.COMMAND_LINE_ARG_PREFIX + "-vbr");
		}

		@Override
		public Option copy() {
			return new VBROption(getValue());
		}
	
	}

	private void createBiosVector(FlatProgramAPI fpa, long laddr, String name, ByteProvider provider, MessageLog log) {
		try {
			Address addr = fpa.toAddr(laddr);
			fpa.getCurrentProgram().getSymbolTable().createLabel(addr, "_bios_" + name + "_vector", SourceType.IMPORTED);
			addr = fpa.toAddr(
					(LittleEndianDataConverter.INSTANCE.getInt(provider.readBytes(laddr & 0xffffff, 4))
							& 0x01FFFFFF) | 0x8C000000l);
			fpa.createFunction(addr, "_bios_" + name + "_syscall");
		} catch (Exception e) {
			log.appendException(e);
		}
	}

	private void createSegments(FlatProgramAPI fpa, MessageLog log) {
		createCcnSegment(fpa, log);
		createUbcSegment(fpa, log);
		createBscSegment(fpa, log);
		createDmacSegment(fpa, log);
		createCpgSegment(fpa, log);
		createRtcSegment(fpa, log);
		createIntcSegment(fpa, log);
		createTmuSegment(fpa, log);
		createSciSegment(fpa, log);
		createScifSegment(fpa, log);
		createHudiSegment(fpa, log);
		createHollyRegsSegment(fpa, log);
		createPvrRegsSegment(fpa, log);
		if (flavor == Flavor.Atomiswave)
			createAtomiswaveRegisters(fpa, log);
		else if (flavor == Flavor.Dreamcast)
			createGDRomRegisters(fpa, log);
		else if (flavor == Flavor.Naomi)
			createNaomiRegisters(fpa, log);
		createAicaRegisters(fpa, true, log);
	}
	
	private static void createCcnSegment(FlatProgramAPI fpa, MessageLog log) {
		createSegment(fpa, null, "CCN", 0xFF000000L, 0x48, true, false, log);
		Namespace ns = createNamespace(fpa, "CCN", log);
		createNamedDword(fpa, 0xFF000000L, "PTEH", "Page table entry high register", log, ns);
		createNamedDword(fpa, 0xFF000004L, "PTEL", "Page table entry low register", log, ns);
		createNamedDword(fpa, 0xFF000008L, "TTB", "Translation table base register", log, ns);
		createNamedDword(fpa, 0xFF00000CL, "TEA", "TLB exception address register", log, ns);
		createNamedDword(fpa, 0xFF000010L, "MMUCR", "MMU control register", log, ns);
		createNamedByte(fpa,  0xFF000014L, "BASRA", "Break ASID register A", log, ns);
		createNamedByte(fpa,  0xFF000018L, "BASRB", "Break ASID register B", log, ns);
		createNamedDword(fpa, 0xFF00001CL, "CCR", "Cache control register", log, ns);
		createNamedDword(fpa, 0xFF000020L, "TRA", "TRAPA exception register", log, ns);
		createNamedDword(fpa, 0xFF000024L, "EXPEVT", "Exception event register", log, ns);
		createNamedDword(fpa, 0xFF000028L, "INTEVT", "Interrupt event register", log, ns);
		createNamedDword(fpa, 0xFF000030L, "PVR", "Processor version register", log, ns);
		createNamedDword(fpa, 0xFF000034L, "PTEA", "Page table entry assistance register", log, ns);
		createNamedDword(fpa, 0xFF000038L, "QACR0", "Queue address control register 0", log, ns);
		createNamedDword(fpa, 0xFF00003CL, "QACR1", "Queue address control register 1", log, ns);
		createNamedDword(fpa, 0xFF000044L, "PRR", "Product register", log, ns);
	}
	
	private static void createUbcSegment(FlatProgramAPI fpa, MessageLog log) {
		createSegment(fpa, null, "UBC", 0xFF200000L, 0x24, true, false, log);
		Namespace ns = createNamespace(fpa, "UBC", log);
		createNamedDword(fpa, 0xFF200000L, "BARA", "Break address register A", log, ns);
		createNamedByte(fpa, 0xFF200004L, "BAMRA", "Break address mask register A", log, ns);
		createNamedWord(fpa, 0xFF200008L, "BBRA", "Break bus cycle register A", log, ns);
		createNamedDword(fpa, 0xFF20000CL, "BARB", "Break address register B", log, ns);
		createNamedByte(fpa, 0xFF200010L, "BAMRB", "Break address mask register B", log, ns);
		createNamedWord(fpa, 0xFF200014L, "BBRB", "Break bus cycle register B", log, ns);
		createNamedDword(fpa, 0xFF200018L, "BDRB", "Break data register B", log, ns);
		createNamedDword(fpa, 0xFF20001CL, "BDMRB", "Break data mask register B", log, ns);
		createNamedWord(fpa, 0xFF200020L, "BRCR", "Break control register", log, ns);
	}
	
	private static void createBscSegment(FlatProgramAPI fpa, MessageLog log) {
		createSegment(fpa, null, "BSC", 0xFF800000L, 0x4C, true, false, log);
		Namespace ns = createNamespace(fpa, "BSC", log);
		createNamedDword(fpa, 0xFF800000L, "BCR1", "Bus control register 1", log, ns);
		createNamedWord(fpa,  0xFF800004L, "BCR2", "Bus control register 2", log, ns);
		createNamedDword(fpa, 0xFF800008L, "WCR1", "Wait state control register 1", log, ns);
		createNamedDword(fpa, 0xFF80000CL, "WCR2", "Wait state control register 2", log, ns);
		createNamedDword(fpa, 0xFF800010L, "WCR3", "Wait state control register 3", log, ns);
		createNamedDword(fpa, 0xFF800014L, "MCR", "Memory control register", log, ns);
		createNamedWord(fpa,  0xFF800018L, "PCR", "PCMCIA control register", log, ns);
		createNamedWord(fpa,  0xFF80001CL, "RTCSR", "Refresh timer control/status register", log, ns);
		createNamedWord(fpa,  0xFF800020L, "RTCNT", "Refresh timer counter", log, ns);
		createNamedWord(fpa,  0xFF800024L, "RTCOR", "Refresh time constant counter", log, ns);
		createNamedWord(fpa,  0xFF800028L, "RFCR", "Refresh count register", log, ns);
		createNamedDword(fpa, 0xFF80002CL, "PCTRA", "Port control register A", log, ns);
		createNamedWord(fpa,  0xFF800030L, "PDTRA", "Port data register A", log, ns);
		createNamedDword(fpa, 0xFF800040L, "PCTRB", "Port control register B", log, ns);
		createNamedWord(fpa,  0xFF800044L, "PDTRB", "Port data register B", log, ns);
		createNamedWord(fpa,  0xFF800048L, "GPIOC", "GPIO interrupt control register", log, ns);
		
		createSegment(fpa, null, "BSC_SDMR2", 0xFF900000L, 0x4, true, false, log);
		createNamedDword(fpa, 0xFF900000L, "SDMR2", "Synchronous DRAM mode registers for area 2", log, ns);
		
		createSegment(fpa, null, "BSC_SDMR2", 0xFF940000L, 0x4, true, false, log);
		createNamedDword(fpa, 0xFF940000L, "SDMR3", "Synchronous DRAM mode registers for area 3", log, ns);
	}
	
	private static void createDmacSegment(FlatProgramAPI fpa, MessageLog log) {
		createSegment(fpa, null, "DMAC", 0xFFA00000L, 0x44, true, false, log);
		Namespace ns = createNamespace(fpa, "DMAC", log);
		createNamedDword(fpa, 0xFFA00000L, "SAR0", "DMA source address register 0", log, ns);
		createNamedDword(fpa, 0xFFA00004L, "DAR0", "DMA destination address register 0", log, ns);
		createNamedDword(fpa, 0xFFA00008L, "DMATCR0", "DMA transfer count register 0", log, ns);
		createNamedDword(fpa, 0xFFA0000CL, "CHCR0", "DMA channel control register 0", log, ns);
		createNamedDword(fpa, 0xFFA00010L, "SAR1", "DMA source address register 1", log, ns);
		createNamedDword(fpa, 0xFFA00014L, "DAR1", "DMA destination address register 1", log, ns);
		createNamedDword(fpa, 0xFFA00018L, "DMATCR1", "DMA transfer count register 1", log, ns);
		createNamedDword(fpa, 0xFFA0001CL, "CHCR1", "DMA channel control register 1", log, ns);
		createNamedDword(fpa, 0xFFA00020L, "SAR2", "DMA source address register 2", log, ns);
		createNamedDword(fpa, 0xFFA00024L, "DAR2", "DMA destination address register 2", log, ns);
		createNamedDword(fpa, 0xFFA00028L, "DMATCR2", "DMA transfer count register 2", log, ns);
		createNamedDword(fpa, 0xFFA0002CL, "CHCR2", "DMA channel control register 2", log, ns);
		createNamedDword(fpa, 0xFFA00030L, "SAR3", "DMA source address register 3", log, ns);
		createNamedDword(fpa, 0xFFA00034L, "DAR3", "DMA destination address register 3", log, ns);
		createNamedDword(fpa, 0xFFA00038L, "DMATCR3", "DMA transfer count register 3", log, ns);
		createNamedDword(fpa, 0xFFA0003CL, "CHCR3", "DMA channel control register 3", log, ns);
		createNamedDword(fpa, 0xFFA00040L, "DMAOR", "DMA operation register", log, ns);
	}
	
	private static void createCpgSegment(FlatProgramAPI fpa, MessageLog log) {
		createSegment(fpa, null, "CPG", 0xFFC00000L, 0x14, true, false, log);
		Namespace ns = createNamespace(fpa, "CPG", log);
		createNamedWord(fpa, 0xFFC00000L, "FRQCR", "Frequency control register", log, ns);
		createNamedByte(fpa, 0xFFC00004L, "STBCR", "Standby control register", log, ns);
		createNamedWord(fpa, 0xFFC00008L, "WTCNT", "Watchdog timer counter", log, ns);
		createNamedWord(fpa, 0xFFC0000CL, "WTCSR", "Watchdog timer control/status register", log, ns);
		createNamedByte(fpa, 0xFFC00010L, "STBCR2", "Standby control register 2", log, ns);
	}
	
	private static void createRtcSegment(FlatProgramAPI fpa, MessageLog log) {
		createSegment(fpa, null, "RTC", 0xFFC80000L, 0x40, true, false, log);
		Namespace ns = createNamespace(fpa, "RTC", log);
		createNamedByte(fpa, 0xFFC80000L, "R64CNT", "64 Hz counter", log, ns);
		createNamedByte(fpa, 0xFFC80004L, "RSECCNT", "Second counter", log, ns);
		createNamedByte(fpa, 0xFFC80008L, "RMINCNT", "Minute counter", log, ns);
		createNamedByte(fpa, 0xFFC8000CL, "RHRCNT", "Hour counter", log, ns);
		createNamedByte(fpa, 0xFFC80010L, "RWKCNT", "Day-of-week counter", log, ns);
		createNamedByte(fpa, 0xFFC80014L, "RDAYCNT", "Day counter", log, ns);
		createNamedByte(fpa, 0xFFC80018L, "RMONCNT", "Month counter", log, ns);
		createNamedWord(fpa, 0xFFC8001CL, "RYRCNT", "Year counter", log, ns);
		createNamedByte(fpa, 0xFFC80020L, "RSECAR", "Second alarm register", log, ns);
		createNamedByte(fpa, 0xFFC80024L, "RMINAR", "Minute alarm register", log, ns);
		createNamedByte(fpa, 0xFFC80028L, "RHRAR", "Hour alarm register", log, ns);
		createNamedByte(fpa, 0xFFC8002CL, "RWKAR", "Day-of-week alarm register", log, ns);
		createNamedByte(fpa, 0xFFC80030L, "RDAYAR", "Day alarm register", log, ns);
		createNamedByte(fpa, 0xFFC80034L, "RMONAR", "Month alarm register", log, ns);
		createNamedByte(fpa, 0xFFC80038L, "RCR1", "RTC control register 1", log, ns);
		createNamedByte(fpa, 0xFFC8003CL, "RCR2", "RTC control register 2", log, ns);
	}
	
	private static void createIntcSegment(FlatProgramAPI fpa, MessageLog log) {
		createSegment(fpa, null, "INTC", 0xFFD00000L, 0x10, true, false, log);
		Namespace ns = createNamespace(fpa, "INTC", log);
		createNamedWord(fpa, 0xFFD00000L, "ICR", "Interrupt control register", log, ns);
		createNamedWord(fpa, 0xFFD00004L, "IPRA", "Interrupt priority register A", log, ns);
		createNamedWord(fpa, 0xFFD00008L, "IPRB", "Interrupt priority register B", log, ns);
		createNamedWord(fpa, 0xFFD0000CL, "IPRC", "Interrupt priority register C", log, ns);
	}
	
	private static void createTmuSegment(FlatProgramAPI fpa, MessageLog log) {
		createSegment(fpa, null, "TMU", 0xFFD80000L, 0x30, true, false, log);
		Namespace ns = createNamespace(fpa, "TMU", log);
		createNamedByte(fpa, 0xFFD80000L, "TOCR", "Timer output control register", log, ns);
		createNamedByte(fpa, 0xFFD80004L, "TSTR", "Timer start register", log, ns);
		createNamedDword(fpa, 0xFFD80008L, "TCOR0", "Timer constant register 0", log, ns);
		createNamedDword(fpa, 0xFFD8000CL, "TCNT0", "Timer counter 0", log, ns);
		createNamedWord(fpa, 0xFFD80010L, "TCR0", "Timer control register 0", log, ns);
		createNamedDword(fpa, 0xFFD80014L, "TCOR1", "Timer constant register 1", log, ns);
		createNamedDword(fpa, 0xFFD80018L, "TCNT1", "Timer counter 1", log, ns);
		createNamedWord(fpa, 0xFFD8001CL, "TCR1", "Timer control register 1", log, ns);
		createNamedDword(fpa, 0xFFD80020L, "TCOR2", "Timer constant register 2", log, ns);
		createNamedDword(fpa, 0xFFD80024L, "TCNT2", "Timer counter 2", log, ns);
		createNamedWord(fpa, 0xFFD80028L, "TCR2", "Timer control register 2", log, ns);
		createNamedDword(fpa, 0xFFD8002CL, "TCPR2", "Input capture register", log, ns);
	}
	
	private static void createSciSegment(FlatProgramAPI fpa, MessageLog log) {
		createSegment(fpa, null, "SCI", 0xFFE00000L, 0x20, true, false, log);
		Namespace ns = createNamespace(fpa, "SCI", log);
		createNamedByte(fpa, 0xFFE00000L, "SCSMR1", "Serial mode register", log, ns);
		createNamedByte(fpa, 0xFFE00004L, "SCBRR1", "Bit rate register", log, ns);
		createNamedByte(fpa, 0xFFE00008L, "SCSCR1", "Serial control register", log, ns);
		createNamedByte(fpa, 0xFFE0000CL, "SCTDR1", "Transmit data register", log, ns);
		createNamedByte(fpa, 0xFFE00010L, "SCSSR1", "Serial status register", log, ns);
		createNamedByte(fpa, 0xFFE00014L, "SCRDR1", "Receive data register", log, ns);
		createNamedByte(fpa, 0xFFE00018L, "SCSCMR1", "Smart card mode register", log, ns);
		createNamedByte(fpa, 0xFFE0001CL, "SCSPTR1", "Serial port register", log, ns);
	}
	
	private static void createScifSegment(FlatProgramAPI fpa, MessageLog log) {
		createSegment(fpa, null, "SCIF", 0xFFE80000L, 0x28, true, false, log);
		Namespace ns = createNamespace(fpa, "SCIF", log);
		createNamedWord(fpa, 0xFFE80000L, "SCSMR2", "Serial mode register", log, ns);
		createNamedByte(fpa, 0xFFE80004L, "SCBRR2", "Bit rate register", log, ns);
		createNamedWord(fpa, 0xFFE80008L, "SCSCR2", "Serial control register", log, ns);
		createNamedByte(fpa, 0xFFE8000CL, "SCFTDR2", "Transmit FIFO data register", log, ns);
		createNamedWord(fpa, 0xFFE80010L, "SCFSR2", "Serial status register", log, ns);
		createNamedByte(fpa, 0xFFE80014L, "SCFRDR2", "Receive FIFO data register", log, ns);
		createNamedWord(fpa, 0xFFE80018L, "SCFCR2", "FIFO control register", log, ns);
		createNamedWord(fpa, 0xFFE8001CL, "SCFDR2", "FIFO data count register", log, ns);
		createNamedWord(fpa, 0xFFE80020L, "SCSPTR2", "Serial port register", log, ns);
		createNamedWord(fpa, 0xFFE80024L, "SCLSR2", "Line status register", log, ns);
	}
	
	private static void createHudiSegment(FlatProgramAPI fpa, MessageLog log) {
		createSegment(fpa, null, "HUDI", 0xFFF00000L, 0x0C, true, false, log);
		Namespace ns = createNamespace(fpa, "HUDI", log);
		createNamedWord(fpa, 0xFFF00000L, "SDIR", "Instruction register", log, ns);
		createNamedDword(fpa, 0xFFF00008L, "SDDR", "Data register", log, ns);
	}

	private static void createHollyRegsSegment(FlatProgramAPI fpa, MessageLog log) {
		createSegment(fpa, null, "HOLLY", 0xA05F6800L, 0x1500, true, false, log);
		Namespace ns = createNamespace(fpa, "HOLLY", log);
		createNamedDword(fpa, 0xA05F6800L, "SB_C2DSTAT", "ch2-DMA destination address", log, ns);
		createNamedDword(fpa, 0xA05F6804L, "SB_C2DLEN", "ch2-DMA length", log, ns);
		createNamedDword(fpa, 0xA05F6808L, "SB_C2DST", "ch2-DMA start", log, ns);
		createNamedDword(fpa, 0xA05F6810L, "SB_SDSTAW", "Sort-DMA start link table address", log, ns);
		createNamedDword(fpa, 0xA05F6814L, "SB_SDBAAW", "Sort-DMA link base address", log, ns);
		createNamedDword(fpa, 0xA05F6818L, "SB_SDWLT", "Sort-DMA link address bit width", log, ns);
		createNamedDword(fpa, 0xA05F681CL, "SB_SDLAS", "Sort-DMA link address shift control", log, ns);
		createNamedDword(fpa, 0xA05F6820L, "SB_SDST", "Sort-DMA start", log, ns);
		
		createNamedDword(fpa, 0xA05F6840L, "SB_DBREQM", "DBREQ# signal mask control", log, ns);
		createNamedDword(fpa, 0xA05F6844L, "SB_BAVLWC", "BAVL# signal wait count", log, ns);
		createNamedDword(fpa, 0xA05F6848L, "SB_C2DPRYC", "DMA (TA/Root Bus) priority count", log, ns);
		createNamedDword(fpa, 0xA05F684CL, "SB_C2DMAXL", "ch2-DMA maximum burst length", log, ns);

		createNamedDword(fpa, 0xA05F6860L, "SB_SDDIV", "Sort-DMA LAT index (guess)", log, ns);

		createNamedDword(fpa, 0xA05F6880L, "SB_TFREM", "TA FIFO remaining amount", log, ns);
		createNamedDword(fpa, 0xA05F6884L, "SB_LMMODE0", "Via TA texture memory bus select 0", log, ns);
		createNamedDword(fpa, 0xA05F6888L, "SB_LMMODE1", "Via TA texture memory bus select 1", log, ns);
		createNamedDword(fpa, 0xA05F688CL, "SB_FFST", "FIFO status", log, ns);
		createNamedDword(fpa, 0xA05F6890L, "SB_SFRES", "System reset", log, ns);
		createNamedDword(fpa, 0xA05F689CL, "SB_SBREV", "System bus revision number", log, ns);
		createNamedDword(fpa, 0xA05F68A0L, "SB_RBSPLT", "SH4 Root Bus split enable", log, ns);

		createNamedDword(fpa, 0xA05F6900L, "SB_ISTNRM", "Normal interrupt status", log, ns);
		createNamedDword(fpa, 0xA05F6904L, "SB_ISTEXT", "External interrupt status", log, ns);
		createNamedDword(fpa, 0xA05F6908L, "SB_ISTERR", "Error interrupt status", log, ns);
		createNamedDword(fpa, 0xA05F6910L, "SB_IML2NRM", "Level 2 normal interrupt mask", log, ns);
		createNamedDword(fpa, 0xA05F6914L, "SB_IML2EXT", "Level 2 external interrupt mask", log, ns);
		createNamedDword(fpa, 0xA05F6918L, "SB_IML2ERR", "Level 2 error interrupt mask", log, ns);
		createNamedDword(fpa, 0xA05F6920L, "SB_IML4NRM", "Level 4 normal interrupt mask", log, ns);
		createNamedDword(fpa, 0xA05F6924L, "SB_IML4EXT", "Level 4 external interrupt mask", log, ns);
		createNamedDword(fpa, 0xA05F6928L, "SB_IML4ERR", "Level 4 error interrupt mask", log, ns);
		createNamedDword(fpa, 0xA05F6930L, "SB_IML6NRM", "Level 6 normal interrupt mask", log, ns);
		createNamedDword(fpa, 0xA05F6934L, "SB_IML6EXT", "Level 6 external interrupt mask", log, ns);
		createNamedDword(fpa, 0xA05F6938L, "SB_IML6ERR", "Level 6 error interrupt mask", log, ns);
		
		createNamedDword(fpa, 0xA05F6940L, "SB_PDTNRM", "Normal interrupt PVR-DMA startup mask", log, ns);
		createNamedDword(fpa, 0xA05F6944L, "SB_PDTEXT", "External interrupt PVR-DMA startup mask", log, ns);
		createNamedDword(fpa, 0xA05F6950L, "SB_G2DTNRM", "Normal interrupt G2-DMA startup mask", log, ns);
		createNamedDword(fpa, 0xA05F6954L, "SB_G2DTEXT", "External interrupt G2-DMA startup mask", log, ns);

		createNamedDword(fpa, 0xA05F6C04L, "SB_MDSTAR", "Maple-DMA command table address", log, ns);
		createNamedDword(fpa, 0xA05F6C10L, "SB_MDTSEL", "Maple-DMA trigger select", log, ns);
		createNamedDword(fpa, 0xA05F6C14L, "SB_MDEN", "Maple-DMA enable", log, ns);
		createNamedDword(fpa, 0xA05F6C18L, "SB_MDST", "Maple-DMA start", log, ns);

		createNamedDword(fpa, 0xA05F6C80L, "SB_MSYS", "Maple system control", log, ns);
		createNamedDword(fpa, 0xA05F6C84L, "SB_MST", "Maple status", log, ns);
		createNamedDword(fpa, 0xA05F6C88L, "SB_MSHTCL", "Maple-DMA hard trigger clear", log, ns);
		createNamedDword(fpa, 0xA05F6C8CL, "SB_MDAPRO", "Maple-DMA address range", log, ns);

		createNamedDword(fpa, 0xA05F6CE8L, "SB_MMSEL", "Maple MSB selection", log, ns);
		createNamedDword(fpa, 0xA05F6CF4L, "SB_MTXDAD", "Maple Txd address counter", log, ns);
		createNamedDword(fpa, 0xA05F6CF8L, "SB_MRXDAD", "Maple Rxd address counter", log, ns);
		createNamedDword(fpa, 0xA05F6CFCL, "SB_MRXDBD", "Maple Rxd base address", log, ns);

		createNamedDword(fpa, 0xA05F7404L, "SB_GDSTAR", "GD-DMA start address", log, ns);
		createNamedDword(fpa, 0xA05F7408L, "SB_GDLEN", "GD-DMA length", log, ns);
		createNamedDword(fpa, 0xA05F740CL, "SB_GDDIR", "GD-DMA direction", log, ns);
		createNamedDword(fpa, 0xA05F7414L, "SB_GDEN", "GD-DMA enable", log, ns);
		createNamedDword(fpa, 0xA05F7418L, "SB_GDST", "GD-DMA start", log, ns);
		createNamedDword(fpa, 0xA05F7480L, "SB_G1RRC", "System ROM read access timing", log, ns);
		createNamedDword(fpa, 0xA05F7484L, "SB_G1RWC", "System ROM write access timing", log, ns);
		createNamedDword(fpa, 0xA05F7488L, "SB_G1FRC", "Flash ROM read access timing", log, ns);
		createNamedDword(fpa, 0xA05F748CL, "SB_G1FWC", "Flash ROM write access timing", log, ns);
		createNamedDword(fpa, 0xA05F7490L, "SB_G1CRC", "GD PIO read access timing", log, ns);
		createNamedDword(fpa, 0xA05F7494L, "SB_G1CWC", "GD PIO write access timing", log, ns);
		createNamedDword(fpa, 0xA05F74A0L, "SB_G1GDRC", "GD-DMA read access timing", log, ns);
		createNamedDword(fpa, 0xA05F74A4L, "SB_G1GDWC", "GD-DMA write access timing", log, ns);

		createNamedDword(fpa, 0xA05F7AB0L, "SB_G1SYSM", "System mode", log, ns);
		createNamedDword(fpa, 0xA05F74B4L, "SB_G1CRDYC", "G1IORDY signal control", log, ns);
		createNamedDword(fpa, 0xA05F74B8L, "SB_GDAPRO", "GD-DMA address range", log, ns);
		
		createNamedDword(fpa, 0xA05F74E4L, "SB_GDROM_UNLOCK", "GDROM unlock", log, ns);
		
		createNamedDword(fpa, 0xA05F74F4L, "SB_GDSTARD", "GD-DMA address count", log, ns);
		createNamedDword(fpa, 0xA05F74F8L, "SB_GDLEND", "GD-DMA transfer counter", log, ns);

		createNamedDword(fpa, 0xA05F7800L, "SB_ADSTAG", "AICA:G2-DMA G2 start address", log, ns);
		createNamedDword(fpa, 0xA05F7804L, "SB_ADSTAR", "AICA:G2-DMA system memory start address", log, ns);
		createNamedDword(fpa, 0xA05F7808L, "SB_ADLEN", "AICA:G2-DMA length", log, ns);
		createNamedDword(fpa, 0xA05F780CL, "SB_ADDIR", "AICA:G2-DMA direction", log, ns);
		createNamedDword(fpa, 0xA05F7810L, "SB_ADTSEL", "AICA:G2-DMA trigger select", log, ns);
		createNamedDword(fpa, 0xA05F7814L, "SB_ADEN", "AICA:G2-DMA enable", log, ns);
		createNamedDword(fpa, 0xA05F7818L, "SB_ADST", "AICA:G2-DMA start", log, ns);
		createNamedDword(fpa, 0xA05F781CL, "SB_ADSUSP", "AICA:G2-DMA suspend", log, ns);

		createNamedDword(fpa, 0xA05F7820L, "SB_E1STAG", "Ext1:G2-DMA G2 start address", log, ns);
		createNamedDword(fpa, 0xA05F7824L, "SB_E1STAR", "Ext1:G2-DMA system memory start address", log, ns);
		createNamedDword(fpa, 0xA05F7828L, "SB_E1LEN", "Ext1:G2-DMA length", log, ns);
		createNamedDword(fpa, 0xA05F782CL, "SB_E1DIR", "Ext1:G2-DMA direction", log, ns);
		createNamedDword(fpa, 0xA05F7830L, "SB_E1TSEL", "Ext1:G2-DMA trigger select", log, ns);
		createNamedDword(fpa, 0xA05F7834L, "SB_E1EN", "Ext1:G2-DMA enable", log, ns);
		createNamedDword(fpa, 0xA05F7838L, "SB_E1ST", "Ext1:G2-DMA start", log, ns);
		createNamedDword(fpa, 0xA05F783CL, "SB_E1SUSP", "Ext1:G2-DMA suspend", log, ns);

		createNamedDword(fpa, 0xA05F7840L, "SB_E2STAG", "Ext2:G2-DMA G2 start address", log, ns);
		createNamedDword(fpa, 0xA05F7844L, "SB_E2STAR", "Ext2:G2-DMA system memory start address", log, ns);
		createNamedDword(fpa, 0xA05F7848L, "SB_E2LEN", "Ext2:G2-DMA length", log, ns);
		createNamedDword(fpa, 0xA05F784CL, "SB_E2DIR", "Ext2:G2-DMA direction", log, ns);
		createNamedDword(fpa, 0xA05F7850L, "SB_E2TSEL", "Ext2:G2-DMA trigger select", log, ns);
		createNamedDword(fpa, 0xA05F7854L, "SB_E2EN", "Ext2:G2-DMA enable", log, ns);
		createNamedDword(fpa, 0xA05F7858L, "SB_E2ST", "Ext2:G2-DMA start", log, ns);
		createNamedDword(fpa, 0xA05F785CL, "SB_E2SUSP", "Ext2:G2-DMA suspend", log, ns);

		createNamedDword(fpa, 0xA05F7860L, "SB_DDSTAG", "Dev:G2-DMA G2 start address", log, ns);
		createNamedDword(fpa, 0xA05F7864L, "SB_DDSTAR", "Dev:G2-DMA system memory start address", log, ns);
		createNamedDword(fpa, 0xA05F7868L, "SB_DDLEN", "Dev:G2-DMA length", log, ns);
		createNamedDword(fpa, 0xA05F786CL, "SB_DDDIR", "Dev:G2-DMA direction", log, ns);
		createNamedDword(fpa, 0xA05F7870L, "SB_DDTSEL", "Dev:G2-DMA trigger select", log, ns);
		createNamedDword(fpa, 0xA05F7874L, "SB_DDEN", "Dev:G2-DMA enable", log, ns);
		createNamedDword(fpa, 0xA05F7878L, "SB_DDST", "Dev:G2-DMA start", log, ns);
		createNamedDword(fpa, 0xA05F787CL, "SB_DDSUSP", "Dev:G2-DMA suspend", log, ns);

		createNamedDword(fpa, 0xA05F7880L, "SB_G2ID", "G2 bus version", log, ns);
		createNamedDword(fpa, 0xA05F7890L, "SB_G2DSTO", "G2/DS timeout", log, ns);
		createNamedDword(fpa, 0xA05F7894L, "SB_G2TRTO", "G2/TR timeout", log, ns);
		createNamedDword(fpa, 0xA05F7898L, "SB_G2MDMTO", "Modem unit wait timeout", log, ns);
		createNamedDword(fpa, 0xA05F789CL, "SB_G2MDMW", "Modem unit wait time", log, ns);

		createNamedDword(fpa, 0xA05F78BCL, "SB_G2APRO", "G2-DMA address range", log, ns);
		createNamedDword(fpa, 0xA05F78C0L, "SB_ADSTAGD", "AICA-DMA address counter (on AICA)", log, ns);
		createNamedDword(fpa, 0xA05F78C4L, "SB_ADSTARD", "AICA-DMA address counter (on root bus)", log, ns);
		createNamedDword(fpa, 0xA05F78C8L, "SB_ADLEND", "AICA-DMA transfer counter", log, ns);
		createNamedDword(fpa, 0xA05F78D0L, "SB_E1STAGD", "Ext-DMA1 address counter (on Ext)", log, ns);
		createNamedDword(fpa, 0xA05F78D4L, "SB_E1STARD", "Ext-DMA1 address counter (on root bus)", log, ns);
		createNamedDword(fpa, 0xA05F78D8L, "SB_E1LEND", "Ext-DMA1 transfer counter", log, ns);
		createNamedDword(fpa, 0xA05F78E0L, "SB_E2STAGD", "Ext-DMA2 address counter (on Ext)", log, ns);
		createNamedDword(fpa, 0xA05F78E4L, "SB_E2STARD", "Ext-DMA2 address counter (on root bus)", log, ns);
		createNamedDword(fpa, 0xA05F78E8L, "SB_E2LEND", "Ext-DMA2 transfer counter", log, ns);
		createNamedDword(fpa, 0xA05F78F0L, "SB_DDSTAGD", "Dev-DMA address counter (on Ext)", log, ns);
		createNamedDword(fpa, 0xA05F78F4L, "SB_DDSTARD", "Dev-DMA address counter (on root bus)", log, ns);
		createNamedDword(fpa, 0xA05F78F8L, "SB_DDLEND", "Dev-DMA transfer counter", log, ns);

		createNamedDword(fpa, 0xA05F7C00L, "SB_PDSTAP", "PVR-DMA PVR start address", log, ns);
		createNamedDword(fpa, 0xA05F7C04L, "SB_PDSTAR", "PVR-DMA system memory start address", log, ns);
		createNamedDword(fpa, 0xA05F7C08L, "SB_PDLEN", "PVR-DMA length", log, ns);
		createNamedDword(fpa, 0xA05F7C0CL, "SB_PDDIR", "PVR-DMA direction", log, ns);
		createNamedDword(fpa, 0xA05F7C10L, "SB_PDTSEL", "PVR-DMA trigger select", log, ns);
		createNamedDword(fpa, 0xA05F7C14L, "SB_PDEN", "PVR-DMA enable", log, ns);
		createNamedDword(fpa, 0xA05F7C18L, "SB_PDST", "PVR-DMA start", log, ns);
		createNamedDword(fpa, 0xA05F7C80L, "SB_PDAPRO", "PVR-DMA address range", log, ns);
		createNamedDword(fpa, 0xA05F7CF0L, "SB_PDSTAPD", "PVR-DMA address counter (on Ext)", log, ns);
		createNamedDword(fpa, 0xA05F7CF4L, "SB_PDSTARD", "PVR-DMA address counter (on root bus)", log, ns);
		createNamedDword(fpa, 0xA05F7CF8L, "SB_PDLEND", "PVR-DMA transfer counter", log, ns);
	}
	
	private static void createPvrRegsSegment(FlatProgramAPI fpa, MessageLog log) {
		createSegment(fpa, null, "PVR", 0xA05F8000L, 0x2000, true, false, log);
		Namespace ns = createNamespace(fpa, "PVR", log);
		createNamedDword(fpa, 0xA05F8000L, "ID", "Device ID", log, ns);
		createNamedDword(fpa, 0xA05F8004L, "REVISION", "", log, ns);
		createNamedDword(fpa, 0xA05F8008L, "SOFTRESET", "CORE & TA software reset", log, ns);
		createNamedDword(fpa, 0xA05F8014L, "STARTRENDER", "Drawing start", log, ns);
		createNamedDword(fpa, 0xA05F8018L, "TEST_SELECT", "PVR Test", log, ns);
		createNamedDword(fpa, 0xA05F8020L, "PARAM_BASE", "Base address for ISP parameters", log, ns);
		createNamedDword(fpa, 0xA05F802CL, "REGION_BASE", "Base address for Region Array", log, ns);
		createNamedDword(fpa, 0xA05F8030L, "SPAN_SORT_CFG", "Span Sorter control", log, ns);
		createNamedDword(fpa, 0xA05F8040L, "VO_BORDER_COL", "Border area color", log, ns);
		createNamedDword(fpa, 0xA05F8044L, "FB_R_CTRL", "Frame buffer read control", log, ns);
		createNamedDword(fpa, 0xA05F8048L, "FB_W_CTRL", "Frame buffer write control", log, ns);
		createNamedDword(fpa, 0xA05F804CL, "FB_W_LINESTRIDE", "Frame buffer line stride", log, ns);
		createNamedDword(fpa, 0xA05F8050L, "FB_R_SOF1", "Read start address for field/strip 1", log, ns);
		createNamedDword(fpa, 0xA05F8054L, "FB_R_SOF2", "Read start address for field/strip 2", log, ns);
		createNamedDword(fpa, 0xA05F805CL, "FB_R_SIZE", "Frame buffer XY size", log, ns);
		createNamedDword(fpa, 0xA05F8060L, "FB_W_SOF1", "Write start address for field/strip 1", log, ns);
		createNamedDword(fpa, 0xA05F8064L, "FB_W_SOF2", "Write start address for field/strip 2", log, ns);
		createNamedDword(fpa, 0xA05F8068L, "FB_X_CLIP", "Pixel clip X coordinate", log, ns);
		createNamedDword(fpa, 0xA05F806CL, "FB_Y_CLIP", "Pixel clip Y coordinate", log, ns);
		createNamedDword(fpa, 0xA05F8074L, "FPU_SHAD_SCALE", "Intensity Volume mode", log, ns);
		createNamedDword(fpa, 0xA05F8078L, "FPU_CULL_VAL", "Comparison value for culling", log, ns);
		createNamedDword(fpa, 0xA05F807CL, "FPU_PARAM_CFG", "Parameter read control", log, ns);
		createNamedDword(fpa, 0xA05F8080L, "HALF_OFFSET", "Pixel sampling control", log, ns);
		createNamedDword(fpa, 0xA05F8084L, "FPU_PERP_VAL", "Comparison value for perpendicular polygons", log, ns);
		createNamedDword(fpa, 0xA05F8088L, "ISP_BACKGND_D", "Background surface depth", log, ns);
		createNamedDword(fpa, 0xA05F808CL, "ISP_BACKGND_T", "Background surface tag", log, ns);

		createNamedDword(fpa, 0xA05F8098L, "ISP_FEED_CFG", "Translucent polygon sort mode", log, ns);
		createNamedDword(fpa, 0xA05F80A0L, "SDRAM_REFRESH", "Texture memory refresh counter", log, ns);
		createNamedDword(fpa, 0xA05F80A4L, "SDRAM_ARB_CFG", "Texture memory arbiter control", log, ns);
		createNamedDword(fpa, 0xA05F80A8L, "SDRAM_CFG", "Texture memory control", log, ns);

		createNamedDword(fpa, 0xA05F80B0L, "FOG_COL_RAM", "Color for Look Up table Fog", log, ns);
		createNamedDword(fpa, 0xA05F80B4L, "FOG_COL_VERT", "Color for vertex Fog", log, ns);
		createNamedDword(fpa, 0xA05F80B8L, "FOG_DENSITY", "Fog scale value", log, ns);
		createNamedDword(fpa, 0xA05F80BCL, "FOG_CLAMP_MAX", "Color clamping maximum value", log, ns);
		createNamedDword(fpa, 0xA05F80C0L, "FOG_CLAMP_MIN", "Color clamping minimum value", log, ns);
		createNamedDword(fpa, 0xA05F80C4L, "SPG_TRIGGER_POS", "External trigger signal HV counter value", log, ns);
		createNamedDword(fpa, 0xA05F80C8L, "SPG_HBLANK_INT", "H-blank interrupt control", log, ns);
		createNamedDword(fpa, 0xA05F80CCL, "SPG_VBLANK_INT", "V-blank interrupt control	", log, ns);
		createNamedDword(fpa, 0xA05F80D0L, "SPG_CONTROL", "Sync pulse generator control", log, ns);
		createNamedDword(fpa, 0xA05F80D4L, "SPG_HBLANK", "H-blank control", log, ns);
		createNamedDword(fpa, 0xA05F80D8L, "SPG_LOAD", "HV counter load value", log, ns);
		createNamedDword(fpa, 0xA05F80DCL, "SPG_VBLANK", "V-blank control", log, ns);
		createNamedDword(fpa, 0xA05F80E0L, "SPG_WIDTH", "Sync width control", log, ns);
		createNamedDword(fpa, 0xA05F80E4L, "TEXT_CONTROL", "Texturing control", log, ns);
		createNamedDword(fpa, 0xA05F80E8L, "VO_CONTROL", "Video output control", log, ns);
		createNamedDword(fpa, 0xA05F80ECL, "VO_STARTX", "Video output start X position", log, ns);
		createNamedDword(fpa, 0xA05F80F0L, "VO_STARTY", "Video output start Y position", log, ns);
		createNamedDword(fpa, 0xA05F80F4L, "SCALER_CTL", "X & Y scaler control", log, ns);

		createNamedDword(fpa, 0xA05F8108L, "PAL_RAM_CTRL", "Palette RAM control", log, ns);
		createNamedDword(fpa, 0xA05F810CL, "SPG_STATUS", "Sync pulse generator status", log, ns);
		createNamedDword(fpa, 0xA05F8110L, "FB_BURSTCTRL", "Frame buffer burst control", log, ns);
		createNamedDword(fpa, 0xA05F8114L, "FB_C_SOF", "Current frame buffer start address", log, ns);
		createNamedDword(fpa, 0xA05F8118L, "Y_COEFF", "Y scaling coefficient", log, ns);
		createNamedDword(fpa, 0xA05F811CL, "PT_ALPHA_REF", "Alpha value for Punch Through polygon comparison", log, ns);

		createNamedDword(fpa, 0xA05F8124L, "TA_OL_BASE", "Object list write start address", log, ns);
		createNamedDword(fpa, 0xA05F8128L, "TA_ISP_BASE", "ISP/TSP Parameter write start address", log, ns);
		createNamedDword(fpa, 0xA05F812CL, "TA_OL_LIMIT", "Start address of next Object Pointer Block", log, ns);
		createNamedDword(fpa, 0xA05F8130L, "TA_ISP_LIMIT", "Current ISP/TSP Parameter write address", log, ns);
		createNamedDword(fpa, 0xA05F8134L, "TA_NEXT_OPB", "Global Tile clip control", log, ns);
		createNamedDword(fpa, 0xA05F8138L, "TA_ITP_CURRENT", "Current ISP/TSP Parameter write address", log, ns);
		createNamedDword(fpa, 0xA05F813CL, "TA_GLOB_TILE_CLIP", "Global Tile clip control", log, ns);
		createNamedDword(fpa, 0xA05F8140L, "TA_ALLOC_CTRL", "Object list control", log, ns);
		createNamedDword(fpa, 0xA05F8144L, "TA_LIST_INIT", "TA initialization", log, ns);
		createNamedDword(fpa, 0xA05F8148L, "TA_YUV_TEX_BASE", "YUV422 texture write start address", log, ns);
		createNamedDword(fpa, 0xA05F814CL, "TA_YUV_TEX_CTRL", "YUV converter control", log, ns);
		createNamedDword(fpa, 0xA05F8150L, "TA_YUV_TEX_CNT", "YUV converter macro block counter value", log, ns);

		createNamedDword(fpa, 0xA05F8160L, "TA_LIST_CONT", "TA continuation processing", log, ns);
		createNamedDword(fpa, 0xA05F8164L, "TA_NEXT_OPB_INIT", "Additional OPB starting address", log, ns);

		createNamedDwords(fpa, 0xA05F8200L, "FOG_TABLE_START", 128, "Fog table", log, ns);
		createNamedDwords(fpa, 0xA05F8600L, "TA_OL_POINTERS_START", 600, "TA object List Pointer data", log, ns);
		createNamedDwords(fpa, 0xA05F9000L, "PALETTE_RAM_START", 1024, "Palette RAM", log, ns);
	}

	private static void createAtomiswaveRegisters(FlatProgramAPI fpa, MessageLog log) {
		Namespace ns = createNamespace(fpa, "AWCART", log);
		createNamedWord(fpa, 0xA05F7000L, "EPR_OFFSETL", "EPR data offset low word", log, ns);
		createNamedWord(fpa, 0xA05F7004L, "EPR_OFFSETH", "EPR data offset hi word", log, ns);
		createNamedWord(fpa, 0xA05F700CL, "MPR_RECORD_INDEX", "File system record index", log, ns);
		createNamedWord(fpa, 0xA05F7010L, "MPR_FIRST_FILE_INDEX", "First file record index", log, ns);
		createNamedWord(fpa, 0xA05F7014L, "MPR_FILE_OFFSETL", "MPR file offset low word", log, ns);
		createNamedWord(fpa, 0xA05F7018L, "MPR_FILE_OFFSETH", "MPR file offset hi word", log, ns);
		createNamedWord(fpa, 0xA05F7080L, "PIO_DATA", "Read/Write word from/to ROM board address space", log, ns);

		createSegment(fpa, null, "AWAVE", 0xA0600000L, 0x800, true, false, log);
		ns = createNamespace(fpa, "AWAVE", log);
		createNamedWord(fpa, 0xA0600280L, "COINCHUTE", "Atomiswave coin chute", log, ns);
		createNamedWord(fpa, 0xA0600284L, "MAPLEDEVS", "Atomiswave maple devices", log, ns);
		createNamedWord(fpa, 0xA0600288L, "UNK288", "Atomiswave unknown", log, ns);
		createNamedWord(fpa, 0xA060028CL, "UNK28C", "Atomiswave unknown", log, ns);
	}

	private static void createGDRomRegisters(FlatProgramAPI fpa, MessageLog log) {
		Namespace ns = createNamespace(fpa, "GDROM", log);
		createNamedWord(fpa, 0xA05F7000L, "IMPEDHI0", "RData bus high imped 0", log, ns);
		createNamedWord(fpa, 0xA05F7004L, "IMPEDHI4", "RData bus high imped 4", log, ns);
		createNamedWord(fpa, 0xA05F7008L, "IMPEDHI8", "RData bus high imped 8", log, ns);
		createNamedWord(fpa, 0xA05F700CL, "IMPEDHIC", "RData bus high imped C", log, ns);
		createNamedWord(fpa, 0xA05F7018L, "DEVCTRL", "Device Control (W) / ALTSTAT (R)", log, ns);
		createNamedWord(fpa, 0xA05F7080L, "DATA", "GD-Rom data", log, ns);
		createNamedWord(fpa, 0xA05F7084L, "ERROR", "Error (R) / FEATURES features (W)", log, ns);
		createNamedWord(fpa, 0xA05F7088L, "IREASON", "Interrupt Reason (W) / SECTCNT Sector count (R)", log, ns);
		createNamedWord(fpa, 0xA05F708CL, "SECTNUM", "Sector Number", log, ns);
		createNamedWord(fpa, 0xA05F7090L, "BYCTLLO", "Byte Control Low", log, ns);
		createNamedWord(fpa, 0xA05F7094L, "BYCTLHI", "Byte Control High", log, ns);
		createNamedWord(fpa, 0xA05F7098L, "DRVSEL", "Unused", log, ns);
		createNamedWord(fpa, 0xA05F709CL, "STATUS", "Status (R) / COMMAND Command (W)", log, ns);
	}

	private static void createNaomiRegisters(FlatProgramAPI fpa, MessageLog log) {
		Namespace ns = createNamespace(fpa, "NAOMI", log);
		// Cart
		createNamedWord(fpa, 0xA05F7000L, "ROM_OFFSETH", "Rom offset high part", log, ns);
		createNamedWord(fpa, 0xA05F7004L, "ROM_OFFSETL", "Rom offset low part", log, ns);
		createNamedWord(fpa, 0xA05F7008L, "ROM_DATA", "Rom data", log, ns);
		createNamedWord(fpa, 0xA05F700CL, "DMA_OFFSETH", "Rom DMA offset high part", log, ns);
		createNamedWord(fpa, 0xA05F7010L, "DMA_OFFSETL", "Rom DMA offset low part", log, ns);
		createNamedWord(fpa, 0xA05F7014L, "DMA_COUNT", "Rom DMA count", log, ns);
		// 840-0001E communication board
		createNamedWord(fpa, 0xA05F7018L, "COMM2_CTRL", "Comm board control register", log, ns);
		createNamedWord(fpa, 0xA05F701CL, "COMM2_OFFSET", "Comm board memory offset", log, ns);
		createNamedWord(fpa, 0xA05F7020L, "COMM2_DATA", "Comm board memory data", log, ns);
		createNamedWord(fpa, 0xA05F7024L, "COMM2_STATUS0", "Comm board status 0", log, ns);
		createNamedWord(fpa, 0xA05F7028L, "COMM2_STATUS1", "Comm board status 1", log, ns);
		// DIMM
		createNamedWord(fpa, 0xA05f703cL, "DIMM_COMMAND", "DIMM command", log, ns);
		createNamedWord(fpa, 0xA05f7040L, "DIMM_OFFSETL", "DIMM offset", log, ns);
		createNamedWord(fpa, 0xA05f7044L, "DIMM_PARAMETERL", "DIMM parameter (low)", log, ns);
		createNamedWord(fpa, 0xA05f7048L, "DIMM_PARAMETERH", "DIMM parameter (high)", log, ns);
		createNamedWord(fpa, 0xA05f704cL, "DIMM_STATUS", "DIMM status", log, ns);
		// Multiboard
		createNamedWord(fpa, 0xA05F7050L, "COMM_OFFSET", "Multiboard offset", log, ns);
		createNamedWord(fpa, 0xA05F7054L, "COMM_DATA", "Multiboard data", log, ns);
		createNamedWord(fpa, 0xA05F7068L, "STATUS_LEDS", "Status LEDs", log, ns);

		createNamedWord(fpa, 0xA05F7078L, "BOARDID_WRITE", "Board ID write", log, ns);
		createNamedWord(fpa, 0xA05F707CL, "BOARDID_READ", "Board ID read", log, ns);
	}
}
