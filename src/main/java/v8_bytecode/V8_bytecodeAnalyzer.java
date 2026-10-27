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

import ghidra.program.model.listing.Listing;
import ghidra.app.cmd.equate.SetEquateCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.symbol.EquateManager;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import v8_bytecode.allocator.NwjcParser;
import v8_bytecode.allocator.ObjectsAllocator;
import v8_bytecode.enums.IntrinsicsEnum;
import v8_bytecode.enums.JsRuntimesEnum;
import v8_bytecode.enums.RuntimesEnum;
import v8_bytecode.enums.TypeOfEnum;
import v8_bytecode.storage.ContextVarStore;
import v8_bytecode.storage.RuntimesIntrinsicsStore;
import v8_bytecode.storage.ScopeInfoStore;
import v8_bytecode.storage.SharedFunctionStore;
import v8_bytecode.storage.FuncsStorage;
import v8_bytecode.storage.InstructionsStorage;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.data.Enum;

import static java.util.Map.entry;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.pcode.JumpTable;
import ghidra.program.model.address.AddressSet;
import ghidra.program.database.function.OverlappingFunctionException;
import java.util.HashMap;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.Variable;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class V8_bytecodeAnalyzer extends AbstractAnalyzer {
	
	private MessageLog2 log2 = new MessageLog2();
	
	private static final Map<String, List<Integer>> CP_FUNCS = Map.ofEntries(
        	entry("LdaNamedProperty", List.of(1)),
        	entry("StaNamedOwnProperty", List.of(1)),
        	entry("StaNamedProperty", List.of(1)),
        	entry("CreateObjectLiteral", List.of(0)),
        	entry("CreateClosure", List.of(0)),
        	entry("LdaConstant", List.of(0)),
        	entry("LdaGlobal", List.of(0)),
        	entry("CallRuntime", List.of(0)),
        	entry("InvokeIntrinsic", List.of(0)),
        	entry("CreateBlockContext", List.of(0)),
        	entry("CreateCatchContext", List.of(1, 2)),
        	entry("SwitchOnSmiNoFeedback", List.of(0)),
        	entry("ThrowReferenceErrorIfHole", List.of(0))
	        );
	
	private static final Map<String, List<Integer>> JUMP_FUNCS = Map.ofEntries(
        	entry("JumpConstant", List.of(0)),
        	entry("JumpIfNullConstant", List.of(0)),
        	entry("JumpIfNotNullConstant", List.of(0)),
        	entry("JumpIfUndefinedConstant", List.of(0)),
        	entry("JumpIfNotUndefinedConstant", List.of(0)),
        	entry("JumpIfTrueConstant", List.of(0)),
        	entry("JumpIfFalseConstant", List.of(0)),
        	entry("JumpIfJSReceiverConstant", List.of(0)),
        	entry("JumpIfToBooleanTrueConstant", List.of(0)),
        	entry("JumpIfToBooleanFalseConstant", List.of(0))
			);
	
	private static final Map<String, List<Integer>> CTX_FUNCS = Map.ofEntries(
			entry("CreateFunctionContext", List.of(0)),
			entry("LdaImmutableCurrentContextSlot", List.of(0)),
			entry("LdaImmutableContextSlot", List.of(1)),
			entry("LdaCurrentContextSlot", List.of(0)),
			entry("LdaContextSlot", List.of(1)),
			entry("StaCurrentContextSlot", List.of(0)),
			entry("StaContextSlot", List.of(1))
			);
	
	private static final List<String> CTX_CHANGER = List.of(
			"PushContext",
			"PopContext"
			);
	
	private static final Map<String, List<Integer>> JSRUN_CALLS = Map.ofEntries(
			entry("CallJSRuntime", List.of(0))
			);
	
	private static final Map<String, List<Integer>> TYPEOFS = Map.ofEntries(
			entry("TestTypeOf", List.of(0))
			);
	
	private FuncsStorage funcsStorage;
	
	public V8_bytecodeAnalyzer() {
		super("V8RefsAnalyzer", "Analyzes refs to ConstantPool, Intrinsics and Runtime functions", AnalyzerType.FUNCTION_ANALYZER);
		setSupportsOneTimeAnalysis();
		setPriority(AnalysisPriority.FORMAT_ANALYSIS);
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return program.getExecutableFormat().equalsIgnoreCase(V8_bytecodeLoader.LDR_NAME);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getExecutableFormat().equalsIgnoreCase(V8_bytecodeLoader.LDR_NAME);
	}
	
	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) throws CancelledException {
		funcsStorage = FuncsStorage.load(program);
		
		final Listing listing = program.getListing();
		final FlatProgramAPI fpa = new FlatProgramAPI(program);
		final FunctionManager mgr = program.getFunctionManager();

		monitor.setIndeterminate(true);

		final String _context = "_context";
		ScopeInfoStore currentScope = null;
		final List<Object[]> slotAccesses = new ArrayList<>();
		
		AddressIterator fiter = set.getAddresses(true);
		
		final List<Object[]> switchTables = new ArrayList<>();

		while (fiter.hasNext()) {
			if (monitor.isCancelled()) {
				break;
			}
			
			final Address addr = fiter.next();

			Instruction instruction = listing.getInstructionAt(addr);
		
			if (instruction == null) {
				continue;
			}

			Function func = mgr.getFunctionContaining(addr);
			
			if (func != null) {
				final String logString = String.format("Applying references for \"%s\"", func.getName());
				monitor.setMessage(logString);
			}
		
			String mnemonic = trimMnemonic(instruction.getMnemonicString());
			// V8 jump targets are relative to the bytecode after a Wide/ExtraWide prefix
			final int prefixOffset = mnemonic.equals(instruction.getMnemonicString()) ? 0 : 1;
			
			// System.out.println(String.format("0x%08X - %s", addr.getOffset(), instruction));
			
			if (LogWriter.isDebug()) {
				log2.appendMsg(String.format("0x%08X - %s", addr.getOffset(), instruction));
			}
			if (hasConstantPoolReference(mnemonic)) {
				for (int opIndex : CP_FUNCS.get(mnemonic)) {
					int index = (int) (instruction.getScalar(opIndex).getValue() & 0xFFFFFFFF);
					instruction.removeOperandReference(opIndex, fpa.toAddr(index));
					switch(mnemonic) {
						case "CallRuntime":
						case "InvokeIntrinsic": {
							final RuntimesIntrinsicsStore runsIntrsStore = funcsStorage.getRuntimesIntrinsicsStore();
							
							final String enumName;
							if (!mnemonic.equals("InvokeIntrinsic")) {
								enumName = runsIntrsStore.getRuntimeName(index);
							} else {
								enumName = runsIntrsStore.getIntrinsicName(index);
							}
							
							log2.appendMsg("enumName: " + enumName);
							
							if (!mnemonic.equals("InvokeIntrinsic")) {
								setEnumOperand(program, RuntimesEnum.NAME, addr, opIndex, index);
							} else {
								setEnumOperand(program, IntrinsicsEnum.NAME, addr, opIndex, index);
							}
						} break;
						case "CreateClosure": {
							Object constItem = funcsStorage.getConstItem(addr, index);
							if (constItem != null) {
	 							final SharedFunctionStore item = (SharedFunctionStore) funcsStorage.getConstItem(addr, index);
								instruction.addOperandReference(opIndex, fpa.toAddr(item.getAddress()), RefType.DATA, SourceType.ANALYSIS);
							} else {
								log2.appendMsg("CreateClosure item is null");
							}
						} break;
						case "CreateBlockContext": {
							final Object scopeItem = funcsStorage.getConstItem(addr, index);
							currentScope = (scopeItem instanceof ScopeInfoStore) ? (ScopeInfoStore) scopeItem : null;

							final long itemOffset = funcsStorage.getConstItemAddress(addr, index);
							if (itemOffset >= 0) {
								instruction.addOperandReference(opIndex, fpa.toAddr(itemOffset), RefType.DATA, SourceType.ANALYSIS);
							}
						} break;
						case "CreateCatchContext": {
							if (opIndex == 2) {
								final Object scopeItem = funcsStorage.getConstItem(addr, index);
								currentScope = (scopeItem instanceof ScopeInfoStore) ? (ScopeInfoStore) scopeItem : null;
							}

							final long itemOffset = funcsStorage.getConstItemAddress(addr, index);
							if (itemOffset >= 0) {
								instruction.addOperandReference(opIndex, fpa.toAddr(itemOffset), RefType.DATA, SourceType.ANALYSIS);
							}
						} break;
						case "SwitchOnSmiNoFeedback": {
							int itemsCount = (int) (instruction.getScalar(opIndex + 1).getValue() & 0xFFFFFFFF);

							final List<Address> refs = new ArrayList<>();
							for (int ic = 0; ic < itemsCount; ++ic) {
								final Object item = funcsStorage.getConstItem(addr, index + ic);
								
								final Address refAddr;
								
								if (!(item instanceof Integer) && !(item instanceof Long)) {
									log2.appendMsg("Unresolved switch table entry " + (index + ic) + " at " + addr);
									continue;
								}
								if (item instanceof Integer) {
									refAddr = addr.add(prefixOffset + NwjcParser.smiToInt((int)item, ObjectsAllocator.getPointerSize(program)));
								} else { // item instanceof Long
									refAddr = addr.add(prefixOffset + NwjcParser.smiToInt((long)item, ObjectsAllocator.getPointerSize(program)));
								}
								
								refs.add(refAddr);
								instruction.addMnemonicReference(refAddr, RefType.COMPUTED_JUMP, SourceType.ANALYSIS);
								ObjectsAllocator.disassemble(program, TaskMonitor.DUMMY, refAddr);
							}
							
							// written by writeSwitchTables once the owning function is known
							switchTables.add(new Object[] { addr, refs });
						} break;
						default: {
						    long constItemAddr = funcsStorage.getConstItemAddress(addr, index);
						    if (constItemAddr < 0) {
						        log2.appendMsg("Constant pool item address is invalid at " + addr + " for index " + index);
						    } else {
						        final Address itemAddr = fpa.toAddr(constItemAddr);
						        instruction.addOperandReference(opIndex, itemAddr, RefType.READ, SourceType.ANALYSIS);
						    }
						}
					}
				}
			} else if (hasContextReference(mnemonic)) {
				for (int opIndex : CTX_FUNCS.get(mnemonic)) {
					int index = (int) (instruction.getScalar(opIndex).getValue() & 0xFFFFFFFF);
					instruction.removeOperandReference(opIndex, fpa.toAddr(index));
					
					RefType refType = RefType.READ;
					
					if (mnemonic.startsWith("Sta")) {
						refType = RefType.WRITE;
					}

					switch (mnemonic) {
					case "CreateFunctionContext": {
						currentScope = funcsStorage.getScopeInfo(addr, _context);
						if (currentScope != null) {
							instruction.addOperandReference(opIndex, fpa.toAddr(currentScope.getOffset()), refType, SourceType.ANALYSIS);
						}
					} break;
					default:
						// resolved by resolveContextSlot once all code is disassembled
						slotAccesses.add(new Object[] { addr, opIndex, refType });
						break;
					}
				}
			} else if (isContextChanger(mnemonic)) {
				// PushContext/PopContext are modelled by ContextTracker
			} else if (isJsRuntimeCaller(mnemonic)) {
				for (int opIndex : JSRUN_CALLS.get(mnemonic)) {
					int index = (int) (instruction.getScalar(opIndex).getValue() & 0xFFFFFFFF);
					instruction.removeOperandReference(opIndex, fpa.toAddr(index));

					setEnumOperand(program, JsRuntimesEnum.NAME, addr, opIndex, index);
				}
			} else if (testsType(mnemonic)) {
				for (int opIndex : TYPEOFS.get(mnemonic)) {
					int index = (int) (instruction.getScalar(opIndex).getValue() & 0xFFFFFFFF);
					
					setEnumOperand(program, TypeOfEnum.NAME, addr, opIndex, index);
				}
			} else if (isJumper(mnemonic)) {
				for (int opIndex : JUMP_FUNCS.get(mnemonic)) {
					log2.appendMsg("Original scalar value at opIndex " + opIndex + ": " + instruction.getScalar(opIndex));
					long rawValue = instruction.getScalar(opIndex).getValue();
					int index = (int) (rawValue & 0xFFFFFFFF);
					log2.appendMsg("Masked index: " + index);
					
					
					//int index = (int) (instruction.getScalar(opIndex).getValue() & 0xFFFFFFFF);
					instruction.removeOperandReference(opIndex, fpa.toAddr(index));
					
					final Object item = funcsStorage.getConstItem(addr, index);
					if (!(item instanceof Integer) && !(item instanceof Long)) {
						log2.appendMsg("Unresolved jump offset constant " + index + " at " + addr);
						continue;
					}
					
					int pointerSize = ObjectsAllocator.getPointerSize(program);
					log2.appendMsg("Pointer size: " + pointerSize);

					int converted;
					if (item instanceof Integer) {
					    converted = NwjcParser.smiToInt((int)item, pointerSize);
					} else {
					    converted = NwjcParser.smiToInt((long)item, pointerSize);
					}
					log2.appendMsg("Converted operand value: " + converted);
					
					final Address refAddr;
					
					if (item instanceof Integer) {
						refAddr = addr.add(prefixOffset + NwjcParser.smiToInt((int)item, ObjectsAllocator.getPointerSize(program)));
					} else { // item instanceof Long
						refAddr = addr.add(prefixOffset + NwjcParser.smiToInt((long)item, ObjectsAllocator.getPointerSize(program)));
					}
					
					boolean jumpConst = mnemonic.equals("JumpConstant");
					
					instruction.addOperandReference(opIndex, refAddr, jumpConst ? RefType.UNCONDITIONAL_JUMP : RefType.CONDITIONAL_JUMP, SourceType.ANALYSIS);
					log2.appendMsg("Calculated reference address: " + refAddr);
					try {
						ObjectsAllocator.disassemble(program, TaskMonitor.DUMMY, refAddr);
					} catch (Exception e) {
						log2.appendMsg("Failed to disassemble at " + refAddr + ": " + e.getMessage());
						byte[] bytes = new byte[16];
						try {
						    program.getMemory().getBytes(refAddr, bytes);
						    log2.appendMsg("Bytes at " + refAddr + ": " + Arrays.toString(bytes));
						} catch (Exception e2) {
						    log2.appendMsg("Failed to dump bytes at " + refAddr + ": " + e2.getMessage());
						}
					}
					
					//ObjectsAllocator.disassemble(program, TaskMonitor.DUMMY, refAddr);
				}
			}
		}

		fixFunctionBodies(program);
		writeSwitchTables(program, switchTables);

		// Always the whole program: a closure's context comes from whichever function creates it,
		// and later passes only cover the code they added.
		final ContextTracker contexts = slotAccesses.isEmpty() ? null
				: new ContextTracker(program, funcsStorage, program.getMemory(), monitor);
		for (final Object[] access : slotAccesses) {
			resolveContextSlot(program, fpa, contexts, (Address) access[0], (int) access[1], (RefType) access[2]);
		}

		for (final Function f : mgr.getFunctions(set, true)) {
			anchorRegisterLocals(program, f);
		}

		monitor.setIndeterminate(false);

		return true;
	}

	/** Points a context-slot operand at the context variable it accesses. */
	private void resolveContextSlot(final Program program, final FlatProgramAPI fpa, final ContextTracker contexts,
			final Address addr, int opIndex, final RefType refType) {
		final Instruction instruction = program.getListing().getInstructionAt(addr);
		if (instruction == null) {
			return;
		}
		final int index = (int) (instruction.getScalar(opIndex).getValue() & 0xFFFFFFFF);
		final ScopeInfoStore scope = contexts.getSlotScope(addr);
		if (scope == null) {
			log2.appendMsg("No context scope for " + instruction + " at " + addr);
			return;
		}
		final ContextVarStore var = scope.getContextVar(index);
		if (var != null) {
			instruction.addOperandReference(opIndex, fpa.toAddr(var.getAddress()), refType, SourceType.ANALYSIS);
		} else if (index >= 4) { // slots 0-3 are the context header, named by V8_ConstantPool
			log2.appendMsg("No context variable " + index + " for " + instruction + " at " + addr + " in " + scope.getName());
		}
		InstructionsStorage.create(program, addr.getOffset(), scope);
	}

	/**
	 * The loader creates each named stack local as a register variable with first use 0. The
	 * decompiler binds a variable only to the value defined exactly at its first-use address, and
	 * "Star rN" is a plain copy of acc that copy propagation deletes. So name the value that is
	 * stored instead: acc as defined by the instruction producing it, or by the merge at the start
	 * of its block. Stores of constants and copies are skipped because the decompiler folds them
	 * away; a loop counter is then named through its increment, which feeds the loop's merge.
	 * Registers written directly by an instruction other than Star/Mov keep a register anchor.
	 */
	private void anchorRegisterLocals(final Program program, final Function func) {
		final Register acc = program.getRegister("acc");
		final List<Instruction> code = ContextTracker.instructions(program, func);

		final Map<Register, List<Integer>> stores = new HashMap<>();
		for (int i = 0; i < code.size(); ++i) {
			for (final Object o : code.get(i).getResultObjects()) {
				if (o instanceof Register && !o.equals(acc)) {
					stores.computeIfAbsent((Register) o, r -> new ArrayList<>()).add(i);
				}
			}
		}

		for (final Variable var : func.getLocalVariables()) {
			final Register reg = var.getRegister();
			if (reg == null || !stores.containsKey(reg)) {
				continue;
			}
			Register storage = null;
			Instruction def = null;
			for (final int store : stores.get(reg)) {
				final String mnemonic = trimMnemonic(code.get(store).getMnemonicString());
				if (mnemonic.equals("Mov")) {
					continue;
				}
				if (!mnemonic.equals("Star")) {
					storage = reg;
					def = code.get(store);
					break;
				}
				final Instruction producer = accProducer(program, code, store);
				if (producer != null && !isConstantOrCopy(producer)) {
					storage = acc;
					def = producer;
					break;
				}
			}
			if (def == null) {
				continue;
			}
			final int use = (int) def.getAddress().subtract(func.getEntryPoint());
			if (storage.equals(reg) && use == var.getFirstUseOffset()) {
				continue;
			}
			try {
				final LocalVariableImpl moved = new LocalVariableImpl(var.getName(), use, var.getDataType(), storage, program);
				func.removeVariable(var);
				func.addLocalVariable(moved, var.getSource());
			} catch (InvalidInputException | DuplicateNameException e) {
				log2.appendMsg("Cannot move local " + var.getName() + " in " + func.getName() + ": " + e.getMessage());
			}
		}
	}

	/**
	 * @return the instruction whose acc value the Star at {@code store} writes: the closest earlier
	 * acc writer, or the instruction starting the block when control merges first (where the
	 * decompiler places the merge); null when acc is not defined in the function.
	 */
	private static Instruction accProducer(final Program program, final List<Instruction> code, final int store) {
		for (int j = store; j >= 0; --j) {
			final Instruction ins = code.get(j);
			if ((j < store && writesAcc(ins)) || isBranchTarget(program, ins.getAddress())) {
				return ins;
			}
		}
		return null;
	}

	/** True if a jump lands here, so the value in acc may be a merge of several definitions. */
	private static boolean isBranchTarget(final Program program, final Address addr) {
		for (final Reference ref : program.getReferenceManager().getReferencesTo(addr)) {
			if (ref.getReferenceType().isFlow()) {
				return true;
			}
		}
		return false;
	}

	/** V8 bytecodes that leave the accumulator unchanged. */
	private static boolean writesAcc(final Instruction ins) {
		final String m = trimMnemonic(ins.getMnemonicString());
		return !(m.startsWith("Sta") || m.startsWith("Jump") || m.equals("Mov") || m.equals("StackCheck")
				|| m.equals("PushContext") || m.equals("PopContext") || m.equals("Nop") || m.equals("Debugger"));
	}

	/** Loads of a constant or of another register into acc, which the decompiler propagates away. */
	private static boolean isConstantOrCopy(final Instruction ins) {
		switch (trimMnemonic(ins.getMnemonicString())) {
		case "LdaZero":
		case "LdaSmi":
		case "LdaConstant":
		case "LdaUndefined":
		case "LdaNull":
		case "LdaTheHole":
		case "LdaTrue":
		case "LdaFalse":
		case "Ldar":
			return true;
		default:
			return false;
		}
	}
	
	/**
	 * The loader creates the functions before their code is disassembled, so on the first pass
	 * their bodies are only the entry point. Grow each one to the code its control flow reaches.
	 */
	private void fixFunctionBodies(final Program program) {
		for (final Function f : program.getFunctionManager().getFunctions(true)) {
			final AddressSet body = new AddressSet();
			for (final Instruction ins : ContextTracker.instructions(program, f)) {
				body.add(ins.getMinAddress(), ins.getMaxAddress());
			}
			if (body.isEmpty() || body.equals(f.getBody())) {
				continue;
			}
			try {
				f.setBody(body);
			} catch (OverlappingFunctionException e) {
				log2.appendMsg("Cannot extend " + f.getName() + ": " + e.getMessage());
			}
		}
	}

	/**
	 * Gives each SwitchOnSmiNoFeedback its targets as a decompiler jump table override: the table
	 * lives in the constant pool, where the decompiler cannot recover it from the p-code. Functions
	 * are looked up through Theia's own ranges, since the first pass runs before Ghidra has grown
	 * the function bodies.
	 */
	@SuppressWarnings("unchecked")
	private void writeSwitchTables(final Program program, final List<Object[]> tables) {
		for (final Object[] table : tables) {
			final Address addr = (Address) table[0];
			final List<Address> targets = (List<Address>) table[1];
			final long entry = funcsStorage.getFunctionOffset(addr);
			final Function func = (entry >= 0) ? program.getFunctionManager().getFunctionAt(addr.getNewAddress(entry)) : null;
			if (func == null || targets.isEmpty()) {
				log2.appendMsg("No jump table for the switch at " + addr);
				continue;
			}
			try {
				new JumpTable(addr, new ArrayList<>(targets), true, 0).writeOverride(func);
			} catch (InvalidInputException e) {
				log2.appendMsg("Cannot write the jump table at " + addr + ": " + e.getMessage());
			}
		}
	}
	
	private DataType setEnumOperand(final Program program, final String dt, final Address addr, int opIndex, int enumIndex) {
		final DataType pre = program.getDataTypeManager().getRootCategory().getDataType(dt);
		final String enumName = EquateManager.formatNameForEquate(pre.getUniversalID(), enumIndex);
		SetEquateCmd eqCmd = new SetEquateCmd(enumName, addr, opIndex, enumIndex);
		eqCmd.applyTo(program);
		return pre;
	}
	
	private static String trimMnemonic(final String mnemonic) {
		int dotPos = mnemonic.indexOf(".");
		
		if (dotPos != -1) {
			return mnemonic.substring(0, dotPos);
		}
		
		return mnemonic;
	}
	
	private static boolean isJsRuntimeCaller(final String mnemonic) {
		return JSRUN_CALLS.containsKey(mnemonic);
	}
	
	private static boolean isContextChanger(final String mnemonic) {
		return CTX_CHANGER.contains(mnemonic);
	}
	
	private static boolean hasContextReference(final String mnemonic) {
		return CTX_FUNCS.containsKey(mnemonic);
	}
	
	private static boolean hasConstantPoolReference(final String mnemonic) {
		return CP_FUNCS.containsKey(mnemonic);
	}
	
	private static boolean testsType(final String mnemonic) {
		return TYPEOFS.containsKey(mnemonic);
	}
	
	private static boolean isJumper(final String mnemonic) {
		return JUMP_FUNCS.containsKey(mnemonic);
	}
	
	@Override
	public void analysisEnded(Program program) {
		super.analysisEnded(program);
		
		if (funcsStorage != null) {
			funcsStorage.store(program);
		}
		
		LogWriter.writeLog(log2, "analyzer.log");
	}
}
