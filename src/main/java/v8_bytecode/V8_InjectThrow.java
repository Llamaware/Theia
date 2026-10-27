package v8_bytecode;

import java.util.Map;

//import ghidra.app.plugin.processors.sleigh.*;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
//import ghidra.app.plugin.processors.sleigh.template.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.InjectPayload;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;
import ghidra.program.model.pcode.PcodeOp;
//import ghidra.xml.*;
import ghidra.xml.XmlElement;
//import ghidra.xml.XmlParseException;
import ghidra.xml.XmlPullParser;

public class V8_InjectThrow extends V8_InjectPayload {
	//protected SleighLanguage language;
	//protected long uniqueBase;

	public V8_InjectThrow(String sourceName, SleighLanguage language, long uniqueBase) {
		super(sourceName, language, uniqueBase);
		this.language = language;
		this.uniqueBase = uniqueBase;
	}

	/** The runtime function each throwing bytecode calls. */
	private static final Map<String, String> RUNTIME_FUNCTIONS = Map.of(
		"Throw", "Throw",
		"ReThrow", "ReThrow",
		"ThrowReferenceErrorIfHole", "ThrowReferenceError",
		"ThrowSuperNotCalledIfHole", "ThrowSuperNotCalled",
		"ThrowSuperAlreadyCalledIfNotHole", "ThrowSuperAlreadyCalledError");

	@Override
	public PcodeOp[] getPcode(Program program, InjectContext context) {
		V8_PcodeOpEmitter pCode = new V8_PcodeOpEmitter(language, context.baseAddr, uniqueBase);
		Address opAddr = context.baseAddr;
		Instruction instruction = program.getListing().getInstructionAt(opAddr);
		if (instruction == null) {
			// The decompiler can follow flow the listing has not disassembled; emit nothing.
			return noOpPayload(context);
		}
		// get arguments from slaspec, definition in cspec
		int condition = (int) context.inputlist.get(0).getOffset();
		int runtimeid = RuntimeIds.get(RUNTIME_FUNCTIONS.getOrDefault(instruction.getMnemonicString().split("\\.")[0], "Throw"));

		if (condition > 0) {
			pCode.emitConditionalBranchVarnode(instruction.getAddress().add(instruction.getLength()), condition, 4, "TheHole");
		}
		// get runtime function
		pCode.emitAssignVarnodeFromPcodeOpCall("call_target", 4, "cpool", "0", "0x" + opAddr.toString(),
				Integer.toString(runtimeid), Integer.toString(RUNTIMETYPE));
		if (instruction.getMnemonicString().startsWith("ThrowReferenceErrorIfHole")) {
			// Runtime::kThrowReferenceError(name)
			int idx = (int) instruction.getScalar(0).getValue();
			pCode.emitAssignVarnodeFromPcodeOpCall("cp", 4, "cpool", "0", "0x" + opAddr.toString(),
					Integer.toString(idx), "0");
			emitCallArgs(pCode, "cp");
		}
		else if (condition == 0) {
			// Throw / ReThrow: the exception is in the accumulator
			emitCallArgs(pCode, "acc");
		}
		pCode.emitVarnodeCall("call_target", 4);
		if (condition == 0) {
			// a throw does not continue with the next instruction
			pCode.emitReturn();
		}
		return pCode.getPcodeOps();
	}

	@Override
	public String getName() {
		// TODO Auto-generated method stub
		return "InjectThrow";
	}

	@Override
	public void encode(Encoder encoder)  {
		// TODO Auto-generated method stub
	}

	@Override
	public boolean isIncidentalCopy() {
		return false;
	}

@Override
	public void restoreXml(XmlPullParser parser, SleighLanguage lang) {
		XmlElement el = parser.start("V8_InjectThrow");
		parser.end(el);
	}

	@Override
	public boolean isEquivalent(InjectPayload obj) {
		if (this.getClass() != obj.getClass()) {
			return false;
		}
		V8_InjectThrow op2 = (V8_InjectThrow) obj;
		if (uniqueBase != op2.uniqueBase) {
			return false;
		}
		return true;
	}
}
