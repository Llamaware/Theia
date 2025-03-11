package v8_bytecode;

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

	@Override
	public PcodeOp[] getPcode(Program program, InjectContext context) {
		Integer callerParamsCount;
		//Integer argIndex = 0;
		Integer callerArgIndex = 0;
		Integer fIdx = 0;
		V8_PcodeOpEmitter pCode = new V8_PcodeOpEmitter(language, context.baseAddr, uniqueBase);
		Address opAddr = context.baseAddr;

		Instruction instruction = program.getListing().getInstructionAt(opAddr);
		// get arguments from slaspec, definition in cspec
		Integer condition = (int) context.inputlist.get(0).getOffset();
		Integer runtimeid = (int) context.inputlist.get(1).getOffset();

		if (condition > 0) {
			pCode.emitConditionalBranchVarnode(instruction.getNext().getAddress(), condition, 4, "TheHole");
		}
		Integer funcType = 0;
		if (instruction.getMnemonicString().compareTo("ThrowReferenceErrorIfHole") == 0) {
			fIdx = 1;
			Integer idx = (int) instruction.getScalar(0).getValue();
			pCode.emitAssignVarnodeFromPcodeOpCall("cp", 4, "cpool", "0", "0x" + opAddr.toString(), idx.toString(),
					funcType.toString());
		}
		// get runtime function
		funcType = 2;
		pCode.emitAssignVarnodeFromPcodeOpCall("call_target", 4, "cpool", "0", "0x" + opAddr.toString(),
				runtimeid.toString(), funcType.toString());
		try {
			callerParamsCount = program.getListing().getFunctionContaining(opAddr).getParameterCount();
		} catch (Exception e) {
			callerParamsCount = 0;
		}
		// get caller args count to save only necessary ones
		// it does not match the logic of the node.exe but important for output quality
		if (callerParamsCount > fIdx + 1) {
			callerParamsCount = fIdx + 1;
		}

		for (; callerArgIndex < callerParamsCount; callerArgIndex++) {
			pCode.emitPushCat1Value("a" + callerArgIndex);
		}
		//argIndex = 0;
		pCode.emitAssignVarnodeFromVarnode("a0", "_context", 4);
		if (fIdx == 1) {
			pCode.emitAssignVarnodeFromVarnode("a1", "_context", 4);
			pCode.emitAssignVarnodeFromVarnode("a0", "cp", 4);
		}
		pCode.emitVarnodeCall("call_target", 4);
		while (callerArgIndex > 0) {
			callerArgIndex--;
			pCode.emitPopCat1Value("a" + callerArgIndex);
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
	public boolean isErrorPlaceholder() {
		return true;
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
