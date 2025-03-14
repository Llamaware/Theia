// @category Analysis
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

public class RenameObfuscatedSymbolsScript extends GhidraScript {

    // Lists of adjectives and nouns to build human-readable names.
    private String[] adjectives = { 
        "Agile", "Brave", "Calm", "Daring", "Eager", "Fierce", "Gentle", "Happy", 
        "Icy", "Jolly", "Kind", "Lively", "Mighty", "Nimble", "Optimal", "Proud", 
        "Quick", "Robust", "Swift", "Tough", "Unique", "Vivid", "Witty", "Xenial", 
        "Young", "Zealous" 
    };

    private String[] nouns = { 
        "Falcon", "Tiger", "Dragon", "Lion", "Eagle", "Shark", "Panther", "Wolf", 
        "Hawk", "Leopard", "Stallion", "Cheetah", "Rhino", "Bear", "Fox", "Viper", 
        "Cobra", "Puma", "Bull", "Raven" 
    };

    /**
     * Converts an obfuscated name (e.g. _0x1e3692) into a human-readable name,
     * appending the original hex part as a suffix to avoid collisions.
     */
    private String computeDeterministicName(String hexName) {
        // Remove the "_0x" prefix.
        String hexPart = hexName.substring(3);
        // Parse the remaining hex string into a long value.
        long value = Long.parseLong(hexPart, 16);
        // Choose an adjective and noun using modulo arithmetic.
        int adjIndex = (int)(value % adjectives.length);
        int nounIndex = (int)((value / adjectives.length) % nouns.length);
        return adjectives[adjIndex] + nouns[nounIndex] + "_" + hexPart;
    }
    
    @Override
    public void run() throws Exception {
        // Pattern to match obfuscated names like _0x1e3692 (case-insensitive)
        Pattern pattern = Pattern.compile("^_0x[0-9a-f]+$", Pattern.CASE_INSENSITIVE);
        int renameCount = 0;
        
        // Rename global symbols
        println("Renaming global symbols...");
        SymbolIterator symIter = currentProgram.getSymbolTable().getAllSymbols(false);
        while (symIter.hasNext() && !monitor.isCancelled()) {
            Symbol sym = symIter.next();
            String name = sym.getName();
            Matcher matcher = pattern.matcher(name);
            if (matcher.matches()) {
                String newName = computeDeterministicName(name);
                try {
                    sym.setName(newName, SourceType.USER_DEFINED);
                    println("Renamed global: " + name + " -> " + newName);
                    renameCount++;
                } catch (Exception e) {
                    println("Failed to rename global " + name + ": " + e.getMessage());
                }
            }
        }
        
        // Rename function names and their local variables/parameters
        println("Renaming symbols in functions...");
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext() && !monitor.isCancelled()) {
            Function func = functions.next();
            // Rename function name if it matches
            String funcName = func.getName();
            Matcher funcMatcher = pattern.matcher(funcName);
            if (funcMatcher.matches()) {
                String newName = computeDeterministicName(funcName);
                try {
                    func.setName(newName, SourceType.USER_DEFINED);
                    println("Renamed function: " + funcName + " -> " + newName);
                    renameCount++;
                } catch (Exception e) {
                    println("Failed to rename function " + funcName + ": " + e.getMessage());
                }
            }
            
            // Rename function parameters
            for (Variable param : func.getParameters()) {
                String paramName = param.getName();
                Matcher paramMatcher = pattern.matcher(paramName);
                if (paramMatcher.matches()) {
                    String newName = computeDeterministicName(paramName);
                    try {
                        param.setName(newName, SourceType.USER_DEFINED);
                        println("Renamed parameter in " + func.getName() + ": " + paramName + " -> " + newName);
                        renameCount++;
                    } catch (Exception e) {
                        println("Failed to rename parameter " + paramName + " in " + func.getName() + ": " + e.getMessage());
                    }
                }
            }
            
            // Rename local variables
            Variable[] locals = func.getLocalVariables();
            for (Variable local : locals) {
                String localName = local.getName();
                Matcher localMatcher = pattern.matcher(localName);
                if (localMatcher.matches()) {
                    String newName = computeDeterministicName(localName);
                    try {
                        local.setName(newName, SourceType.USER_DEFINED);
                        println("Renamed local variable in " + func.getName() + ": " + localName + " -> " + newName);
                        renameCount++;
                    } catch (Exception e) {
                        println("Failed to rename local variable " + localName + " in " + func.getName() + ": " + e.getMessage());
                    }
                }
            }
        }
        println("Renaming complete. Total renamed: " + renameCount);
    }
}
