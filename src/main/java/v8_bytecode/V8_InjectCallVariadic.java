package v8_bytecode;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.InjectPayload;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
//import ghidra.xml.XmlParseException;
import ghidra.xml.XmlPullParser;
import ghidra.xml.XmlElement;

public class V8_InjectCallVariadic extends V8_InjectPayload {
	//protected SleighLanguage language;
	//protected long uniqueBase;

public V8_InjectCallVariadic(String sourceName, SleighLanguage language, long uniqueBase) {
		super(sourceName, language, uniqueBase);
		this.language = language;
		this.uniqueBase = uniqueBase;
	}

//	public V8_InjectInvokeIntrinsicCallRuntime(String sourceName, SleighLanguage language) {
//		super(sourceName, language);
//		// TODO Auto-generated constructor stub
//	}


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
		int funcType = (int) context.inputlist.get(0).getOffset();
		String target;
		if (funcType != PROPERTYTYPE) {
			// runtime/intrinsic id, resolved to the function through the constant pool
			int index = (int) instruction.getScalar(0).getValue();
			pCode.emitAssignVarnodeFromPcodeOpCall("call_target", 4, "cpool", "0", "0x" + opAddr.toString(),
					Integer.toString(index), Integer.toString(funcType));
			target = "call_target";
		}
		else {
			target = instruction.getRegister(0).getName();
		}
		// The range already starts with the receiver for CallProperty/CallAnyReceiver/CallWithSpread,
		// and holds only the arguments for CallUndefinedReceiver and runtime/intrinsic calls.
		emitCallArgs(pCode, getRangeRegisters(instruction, 2));
		pCode.emitVarnodeCall(target, 4);
		return pCode.getPcodeOps();
	}

	@Override
	public boolean isIncidentalCopy() {
		return false;
	}
	
@Override
	public void restoreXml(XmlPullParser parser, SleighLanguage lang){
		XmlElement el = parser.start("V8_InjectCallJSRuntime");
		parser.end(el);
	}
	@Override
	public String getName() {
		// TODO Auto-generated method stub
		return "InjectCallVariadic";
	}
	@Override
	public boolean isEquivalent(InjectPayload obj) {
		if (this.getClass() != obj.getClass()) {
			return false;
		}
		V8_InjectCallVariadic op2 = (V8_InjectCallVariadic) obj;
		if (uniqueBase != op2.uniqueBase) {
			return false;
		}
		return true;
	}
}
