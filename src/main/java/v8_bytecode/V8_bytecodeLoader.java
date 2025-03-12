/* ###
 * IP: GHIDRA
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
package v8_bytecode;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
//import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import ghidra.app.util.bin.BinaryReader;
import v8_bytecode.allocator.ObjectsAllocator;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.framework.options.Options;
import v8_bytecode.allocator.NwjcParser;

//import v8_bytecode.MessageLog2;

/**
 * Provide class-level documentation that describes what this loader does.
 */
public class V8_bytecodeLoader extends AbstractProgramWrapperLoader {
	private static final long INSTANCE_SIZE = 0x3D2L;
	static final String LDR_NAME = "Nwjc (.bin) Loader";
	private NwjcParser parser = null;

	@Override
	public String getName() {

		// Name the loader.  This name must match the name of the loader in the .opinion files.

		return LDR_NAME;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		// Examine the bytes in 'provider' to determine if this loader can load it.  If it 
		// can load it, return the appropriate load specifications.
		
		BinaryReader reader = new BinaryReader(provider, true);

		long magic = reader.readNextUnsignedInt();

		if (magic == (0xC0DE0000L ^ INSTANCE_SIZE)) {
			loadSpecs.add(new LoadSpec(this, ObjectsAllocator.CODE_BASE, new LanguageCompilerSpecPair("V8:LE:32:default", "default"), true));
		}

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {

		Options aOpts = program.getOptions(Program.ANALYSIS_PROPERTIES);
		aOpts.setBoolean("Decompiler Switch Analysis", false);

		BinaryReader reader = new BinaryReader(provider, true);
		
		MessageLog2 log2 = new MessageLog2();

		try {
			final String descr = program.getLanguage().getLanguageDescription().getVariant();
			log.appendMsg("Language variant descr: " + descr);
			parser = new NwjcParser(reader, descr.equalsIgnoreCase("x32"), program, monitor, log2);
			parser.parse();
			parser.postAllocate();
			String currentDirectory = System.getProperty("user.dir");
			log2.writeToFile(currentDirectory + "\\loader.log");
			log.appendMsg("Debug log written to " + currentDirectory + "\\loader.log");
		} catch (Exception e) {
			e.printStackTrace();
			log2.appendException(e);
			String currentDirectory = System.getProperty("user.dir");
			log2.writeToFile(currentDirectory + "\\loader.log");
			log.appendMsg("An error occurred. Debug log written to " + currentDirectory + "\\loader.log");
		}
	}
}
