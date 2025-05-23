package v8_bytecode;

import java.util.ArrayList;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.lang.InjectPayload;
import ghidra.xml.XmlPullParser;
import ghidra.xml.XmlElement;

public class V8_InjectJSCallN extends V8_InjectPayload {
	//protected SleighLanguage language;
	//protected long uniqueBase;

	public V8_InjectJSCallN(String sourceName, SleighLanguage language, long uniqueBase) {
		super(sourceName, language, uniqueBase);
		this.language = language;
		this.uniqueBase = uniqueBase;
	}

	@Override
	public PcodeOp[] getPcode(Program program, InjectContext context) {
		Integer callerParamsCount;
		Integer argIndex = 0;
		Integer callerArgIndex = 0;

		V8_PcodeOpEmitter pCode = new V8_PcodeOpEmitter(language, context.baseAddr, uniqueBase);
		Address opAddr = context.baseAddr;
		Instruction instruction = program.getListing().getInstructionAt(opAddr);
		// get arguments from slaspec, definition in cspec
		Integer argcount = (int) context.inputlist.get(0).getOffset();
		Integer receiver = (int) context.inputlist.get(1).getOffset();

		ArrayList<Object> opArrList = new ArrayList<Object>();
		for (int i = 0; i < argcount; i++) {
			opArrList.add(instruction.getOpObjects(i + receiver + 1)[0]);
		}
		// PcodeOp[] p = instruction.getPcode();
		Object[] opObjects = opArrList.toArray();
		try {
			callerParamsCount = program.getListing().getFunctionContaining(opAddr).getParameterCount();
		} catch (Exception e) {
			callerParamsCount = 0;
		}
		// get caller args count to save only necessary ones
		// it does not match the logic of the node.exe but important for output quality
		if (callerParamsCount > opObjects.length) {
			callerParamsCount = opObjects.length;
		}
		for (; callerArgIndex < callerParamsCount; callerArgIndex++) {
			pCode.emitPushCat1Value("a" + callerArgIndex);
		}
		// save instruction operands in locals
		argIndex = opObjects.length;
		for (Object o : opObjects) {
			argIndex--;
			Register currentOp = (Register) o;
			String invokeTmp = "invoke_tmp_" + "a" + argIndex;
			pCode.emitAssignVarnodeFromVarnode(invokeTmp, currentOp.toString(), 4);
		}
		// writing locals into aX registers to avoid mixing up arguments
		argIndex = opObjects.length;
		for (int i = 0; i < opObjects.length; i++) {
			argIndex--;
			//Register currentOp = (Register) o;
			String invokeTmp = "invoke_tmp_" + "a" + argIndex;
			pCode.emitAssignVarnodeFromVarnode("a" + argIndex, invokeTmp, 4);
		}
		// make call
		pCode.emitVarnodeCall(instruction.getRegister(0).toString(), 4);

		while (callerArgIndex > 0) {
			callerArgIndex--;
			pCode.emitPopCat1Value("a" + callerArgIndex);
		}
		if (receiver == 1) {
			Register currentOp = (Register) instruction.getOpObjects(1)[0];
			pCode.emitAssignVarnodeFromVarnode(currentOp.toString(), "acc", 4);
		}
		return pCode.getPcodeOps();
	}

	@Override
	public void restoreXml(XmlPullParser parser, SleighLanguage lang){
		XmlElement el = parser.start("V8_InjectCallJSRuntime");
		parser.end(el);
	}
	@Override
	public String getName() {
		// TODO Auto-generated method stub
		return "InjectJSCallN";
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
	public boolean isEquivalent(InjectPayload obj) {
		if (this.getClass() != obj.getClass()) {
			return false;
		}
		V8_InjectJSCallN op2 = (V8_InjectJSCallN) obj;
		if (uniqueBase != op2.uniqueBase) {
			return false;
		}
		return true;
	}
}
