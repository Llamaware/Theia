package v8_bytecode;
import java.io.File;
import java.util.Date;

public class LogWriter {
	
	public static String writeLog(MessageLog2 log, String fileName){
		String currentDirectory = System.getProperty("user.dir");
		File theiaDir = new File(currentDirectory + "\\Theia");
		if (!theiaDir.exists()){
		    theiaDir.mkdirs();
		}
		String resultPath = currentDirectory + "\\Theia\\" + fileName;
		String firstMessage = log.getFirstMsg();
		if (firstMessage.contains("Log written by Theia")) {
			log.deleteFirstMsg();
		}
		log.prependMsg("---Log written by Theia - " + V8_bytecodeLoader.buildName() + " at " + new Date() + "---");
		log.writeToFile(resultPath);
		return resultPath;
	}
}