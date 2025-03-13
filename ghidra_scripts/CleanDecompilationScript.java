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
        
        for (Function func : currentProgram.getFunctionManager().getFunctions(true)) {
            println("Processing function: " + func.getName());
            
            DecompileResults results = decompInterface.decompileFunction(func, 60, monitor);
            if (!results.decompileCompleted()) {
                println("Decompilation failed for " + func.getName());
                continue;
            }
            
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
            
            // Similarly, do the same for LdaNamedProperty if needed.
            cleanedCode = cleanedCode.replaceAll(
                "(\\w+\\s*=\\s*)LdaNamedProperty\\s*\\(\\s*(\\w+)\\s*,\\s*\"([^\"]+)\"\\s*\\)",
                "$1$2.$3"
            );
            cleanedCode = cleanedCode.replaceAll(
                "(\\w+\\s*=\\s*)LdaNamedProperty\\s*\\(\\s*(\\w+)\\s*,\\s*([a-zA-Z_][\\w]*)\\s*\\)",
                "$1$2[$3]"
            );
            
            println("Cleaned decompilation for function: " + func.getName());
            println(cleanedCode);
        }
        
        decompInterface.dispose();
    }
}
