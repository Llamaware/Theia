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

/**
 * Provide class-level documentation that describes what this loader does.
 */
public class V8_bytecodeLoader extends AbstractProgramWrapperLoader {
	private static final long INSTANCE_SIZE = 0x3D2L;
	static final String LDR_NAME = "NWBin (.bin) Loader";
	private NwjcParser parser = null;

	@Override
	public String getName() {
		return LDR_NAME;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		// Examine the bytes in 'provider' to determine if this loader can load it.  If it 
		// can load it, return the appropriate load specifications.
		
		BinaryReader reader = new BinaryReader(provider, true);

		long magic = reader.readNextUnsignedInt();

		if (magic == (0xC0DE0000L ^ INSTANCE_SIZE)) { // only supports x32 right now
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
		log.appendMsg("Welcome to Theia - " + LogWriter.buildName());
		log.appendMsg("I've initialized the loader.");
		
		try {
			final String descr = program.getLanguage().getLanguageDescription().getVariant();
			log2.appendMsg("Language variant descr: " + descr);
			parser = new NwjcParser(reader, descr.equalsIgnoreCase("x32"), program, monitor, log2);
			parser.parse();
			parser.postAllocate();
			String logResult = LogWriter.writeLog(log2, "loader.log");
			log.appendMsg("Load complete, everything okay!\nDebug log written to:\n" + logResult);
		} catch (Exception e) {
			e.printStackTrace();
			log2.appendException(e);
			String logResult = LogWriter.writeLog(log2, "loader.log");
			log.appendMsg("Something went wrong!");
			log.appendMsg(e.getMessage());
			log.appendMsg("Debug log written to:\n" + logResult);
		}
	}
}
