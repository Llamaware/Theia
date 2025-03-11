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

public class V8_InjectConstruct extends V8_InjectPayload {
	//protected SleighLanguage language;
	//protected long uniqueBase;

	public V8_InjectConstruct(String sourceName, SleighLanguage language, long uniqueBase) {
		super(sourceName, language, uniqueBase);
		this.language = language;
		this.uniqueBase = uniqueBase;
	}

	@Override
	public String getName() {
		return "ConstructCallOther";
	}

	@Override
	public void restoreXml(XmlPullParser parser, SleighLanguage lang){
		XmlElement el = parser.start("V8_InjectCallJSRuntime");
		parser.end(el);
	}
	@Override
	public PcodeOp[] getPcode(Program program, InjectContext context) {
		V8_PcodeOpEmitter pCode = new V8_PcodeOpEmitter(language, context.baseAddr, uniqueBase); 	
		Address opAddr = context.baseAddr;
		Instruction instruction = program.getListing().getInstructionAt(opAddr);
		Integer opIndex = 2;
		Object[] opObjects = instruction.getOpObjects(opIndex);
		String[] args = new String[opObjects.length + 1];
		args[0] = instruction.getRegister(0).toString();
		for(int i=0; i < opObjects.length; i++) {
			args[i+1] = ((Register)opObjects[i]).toString();
		}
		pCode.emitAssignVarnodeFromPcodeOpCall("acc", 4, "Construct", args);
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
	public boolean isEquivalent(InjectPayload obj) {
		if (this.getClass() != obj.getClass()) {
			return false;
		}
		V8_InjectConstruct op2 = (V8_InjectConstruct) obj;
		if (uniqueBase != op2.uniqueBase) {
			return false;
		}
		return true;
	}
}
