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
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class DreamcastAicaLoader extends BaseLoader {
	long ramSize = 2 * MB;

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
	
		BinaryReader reader = new BinaryReader(provider, true);
		
		long size = reader.length();
		if (size == 2 * MB || size == 8 * MB) {
			loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("ARM:LE:32:v4", "default"), true));
			ramSize = size;
		}

		return loadSpecs;
	}

	@Override
	public String getName() {
		return "Dreamcast/Naomi AICA loader";
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program,
			TaskMonitor monitor, MessageLog log) throws CancelledException, IOException {
		FlatProgramAPI fpa = new FlatProgramAPI(program);
		createAicaRegisters(fpa, false, log);
		
		InputStream ramStream = provider.getInputStream(0L);
		createSegment(fpa, ramStream, "RAM", 0, ramSize, true, true, log);
	}
}
