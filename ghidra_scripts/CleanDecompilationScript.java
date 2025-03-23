//Print selected function to console in a more legible format.
// @author Llamaware
// @category Analysis
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.app.script.GhidraScript;

public class CleanDecompilationScript extends GhidraScript {

    @Override
    public void run() throws Exception {
        DecompInterface decompInterface = new DecompInterface();
        decompInterface.openProgram(currentProgram);
        
        try {
            Function func = currentProgram.getFunctionManager().getFunctionContaining(currentAddress);
        	
            println("Processing function: " + func.getName());
            
            DecompileResults results = decompInterface.decompileFunction(func, 30, monitor);
            
            String decompiledCode = results.getDecompiledFunction().getC();
            
            // Replace calls with literal property names (using dot notation)
            String cleanedCode = decompiledCode.replaceAll(
                "(\\w+\\s*=\\s*)GetNamedProperty\\s*\\(\\s*(\\w+)\\s*,\\s*\"([^\"]+)\"\\s*\\)",
                "$1$2.$3"
            );
            
            // Replace calls with variable property names (using bracket notation)
            cleanedCode = cleanedCode.replaceAll(
                "(\\w+\\s*=\\s*)GetNamedProperty\\s*\\(\\s*(\\w+)\\s*,\\s*([a-zA-Z_][\\w]*)\\s*\\)",
                "$1$2[$3]"
            );
            
            // Handle LdaNamedProperty calls, now with an optional cast (e.g. (code *))
            // For literal property names (using dot notation)
            cleanedCode = cleanedCode.replaceAll(
                "(\\w+\\s*=\\s*)(\\([^)]*\\)\\s*)?LdaNamedProperty\\s*\\(\\s*(\\w+)\\s*,\\s*\"([^\"]+)\"\\s*\\)",
                "$1$3.$4"
            );
            // For variable property names (using bracket notation)
            cleanedCode = cleanedCode.replaceAll(
                "(\\w+\\s*=\\s*)(\\([^)]*\\)\\s*)?LdaNamedProperty\\s*\\(\\s*(\\w+)\\s*,\\s*([a-zA-Z_][\\w]*)\\s*\\)",
                "$1$3[$4]"
            );
            
            println("Cleaned decompilation for function: " + func.getName());
            println(cleanedCode);
        } finally {
			decompInterface.dispose();
		}
    }
}
