package v8_bytecode;
import java.io.File;
import java.util.Date;

public class LogWriter {
	
	static final String BUILD_NAME = "v1.0-rc1 \"Skyclad Observer\" (Release Candidate)";
	
	public static String buildName() {
		return BUILD_NAME;
	}
	
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
		log.prependMsg("---Log written by Theia - " + buildName() + " at " + new Date() + "---");
		log.writeToFile(resultPath);
		return resultPath;
	}
}