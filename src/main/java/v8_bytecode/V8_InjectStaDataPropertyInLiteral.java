package v8_bytecode;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.InjectPayload;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;
public class V8_InjectStaDataPropertyInLiteral extends V8_InjectPayload {
	//protected SleighLanguage language;
	//protected long uniqueBase;

	public V8_InjectStaDataPropertyInLiteral(String sourceName, SleighLanguage language, long uniqueBase) {
		super(sourceName, language, uniqueBase);
		this.language = language;
		this.uniqueBase = uniqueBase;
	}

	@Override
	public PcodeOp[] getPcode(Program program, InjectContext context) {
		Integer callerParamsCount;
		//Integer argIndex = 0;
		Integer callerArgIndex = 0;
		Integer caleeArgsCount = 5;
		Integer runtimeType = 2;
		Integer index = 323; // Runtime::kDefineDataPropertyInLiteral
		V8_PcodeOpEmitter pCode = new V8_PcodeOpEmitter(language, context.baseAddr, uniqueBase);
		Address opAddr = context.baseAddr;
		Instruction instruction = program.getListing().getInstructionAt(opAddr);
		try {
			callerParamsCount = program.getListing().getFunctionContaining(opAddr).getParameterCount();
		} catch (Exception e) {
			callerParamsCount = 0;
		}
		// get caller args count to save only necessary ones
		// it does not match the logic of the node.exe but important for output quality
		pCode.emitAssignVarnodeFromPcodeOpCall("call_target", 4, "cpool", "0", "0x" + opAddr.toString(),
				index.toString(),
				runtimeType.toString());
		if (callerParamsCount > caleeArgsCount) {
			callerParamsCount = caleeArgsCount;
		}
		for (; callerArgIndex < callerParamsCount; callerArgIndex++) {
			pCode.emitPushCat1Value("a" + callerArgIndex);
		}
		// save instruction operands in locals
		String invokeTmp = "invoke_tmp_" + "obj";
		pCode.emitAssignVarnodeFromVarnode(invokeTmp, instruction.getRegister(0).toString(), 4);
		invokeTmp = "invoke_tmp_" + "name";
		pCode.emitAssignVarnodeFromVarnode(invokeTmp, instruction.getRegister(1).toString(), 4);
		pCode.emitAssignVarnodeFromVarnode("a0", "_context", 4);
		pCode.emitAssignVarnodeFromVarnode("a1", "invoke_tmp_obj", 4);
		pCode.emitAssignVarnodeFromVarnode("a2", "invoke_tmp_name", 4);
		pCode.emitAssignVarnodeFromVarnode("a3", "acc", 4);
		pCode.emitAssignConstantToRegister("a4", (int) instruction.getScalar(2).getValue());
		// make call
		pCode.emitVarnodeCall("call_target", 4);

		while (callerArgIndex > 0) {
			callerArgIndex--;
			pCode.emitPopCat1Value("a" + callerArgIndex);
		}
		return pCode.getPcodeOps();
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
	public String getName() {
		// TODO Auto-generated method stub
		return "InjectStaDataPropertyInLiteral";
	}
	@Override
	public void restoreXml(XmlPullParser parser, SleighLanguage lang){
		XmlElement el = parser.start("V8_InjectStaDataPropertyInLiteral");
		parser.end(el);
	}
	@Override	
	public boolean isEquivalent(InjectPayload obj) {
		if (this.getClass() != obj.getClass()) {
			return false;
		}
		V8_InjectStaDataPropertyInLiteral op2 = (V8_InjectStaDataPropertyInLiteral) obj;
		if (uniqueBase != op2.uniqueBase) {
			return false;
		}
		return true;
	}
}
