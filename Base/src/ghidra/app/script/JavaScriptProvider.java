/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.script;

import java.io.*;
import java.util.*;

import javax.tools.*;
import javax.tools.JavaCompiler.CompilationTask;
import javax.tools.JavaFileObject.Kind;

import generic.io.NullPrintWriter;
import generic.jar.*;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.util.Msg;

public class JavaScriptProvider extends GhidraScriptProvider {

	private JavaScriptClassLoader loader = new JavaScriptClassLoader();

	@Override
	public String getDescription() {
		return "Java";
	}

	@Override
	public String getExtension() {
		return ".java";
	}

	@Override
	public boolean deleteScript(ResourceFile scriptSource) {
		// Assuming script is in default java package, so using script's base name as class name.
		File clazzFile = getClassFile(scriptSource, GhidraScriptUtil.getBaseName(scriptSource));
		clazzFile.delete();
		return super.deleteScript(scriptSource);
	}

	@Override
	public GhidraScript getScriptInstance(ResourceFile sourceFile, PrintWriter writer)
			throws ClassNotFoundException, InstantiationException, IllegalAccessException {

		if (writer == null) {
			writer = new NullPrintWriter();
		}

		// Assuming script is in default java package, so using script's base name as class name.
		File clazzFile = getClassFile(sourceFile, GhidraScriptUtil.getBaseName(sourceFile));
		if (needsCompile(sourceFile, clazzFile)) {
			compile(sourceFile, writer); // may throw an exception
		}
		else if (scriptCompiledExternally(clazzFile)) {
			forceClassReload();
		}

		String clazzName = GhidraScriptUtil.getBaseName(sourceFile);

		Class<?> clazz = null;
		try {
			clazz = Class.forName(clazzName, true, loader);
		}
		catch (GhidraScriptUnsupportedClassVersionError e) {
			// Unusual Code Alert!: This implies the script was compiled in a newer
			// version of Java.  So, just delete the class file and try again.
			ResourceFile classFile = e.getClassFile();
			classFile.delete();
			return getScriptInstance(sourceFile, writer);
		}

		Object object = clazz.newInstance();
		if (object instanceof GhidraScript) {
			GhidraScript script = (GhidraScript) object;
			script.setSourceFile(sourceFile);
			return script;
		}

		String message = "Not a valid Ghidra script: " + sourceFile.getName();
		writer.println(message);
		Msg.error(this, message); // the writer may not be the same as Msg, so log it too
		return null; // class is not a script
	}

	private void forceClassReload() {
		loader = new JavaScriptClassLoader(); // this forces the script class to be reloaded
	}

	/**
	 * Gets the class file corresponding to the given source file and class name.  
	 * If the class is in a package, the class name should include the full 
	 * package name.
	 * 
	 * @param sourceFile The class's source file.
	 * @param className The class's name (including package if applicable).
	 * @return The class file corresponding to the given source file and class name. 
	 */
	protected File getClassFile(ResourceFile sourceFile, String className) {
		ResourceFile resourceFile =
			GhidraScriptUtil.getClassFileByResourceFile(sourceFile, className);

		File file = resourceFile.getFile(false);
		return file;
	}

	protected boolean needsCompile(ResourceFile sourceFile, File classFile) {

		// Need to compile if there is no class file.
		if (!classFile.exists()) {
			return true;
		}

		// Need to compile if the script's source file is newer than its corresponding class file.
		if (sourceFile.lastModified() > classFile.lastModified()) {
			return true;
		}

		// Need to compile if parent classes are not up to date.
		return !areAllParentClassesUpToDate(sourceFile);
	}

	protected boolean scriptCompiledExternally(File classFile) {

		Long modifiedTimeWhenLoaded = loader.lastModified(classFile);
		if (modifiedTimeWhenLoaded == null) {
			// never been loaded, so doesn't matter
			return false;
		}

		if (classFile.lastModified() > modifiedTimeWhenLoaded) {
			return true;
		}

		return false;
	}

	private boolean areAllParentClassesUpToDate(ResourceFile sourceFile) {

		List<Class<?>> parentClasses = getParentClasses(sourceFile);
		if (parentClasses == null) {
			// some class is missing!
			return false;
		}

		if (parentClasses.isEmpty()) {
			// nothing to do--no parent class to re-compile
			return true;
		}

		// check each parent for modification
		for (Class<?> clazz : parentClasses) {
			ResourceFile parentFile = getSourceFile(clazz);
			if (parentFile == null) {
				continue; // not sure if this can happen (inner-class, maybe?)
			}

			// Parent class might have a non-default java package, so use class's full name.
			File clazzFile = getClassFile(parentFile, clazz.getName());

			if (parentFile.lastModified() > clazzFile.lastModified()) {
				return false;
			}
		}

		return true;
	}

	protected boolean compile(ResourceFile sourceFile, final PrintWriter writer)
			throws ClassNotFoundException {

		ScriptInfo info = GhidraScriptUtil.getScriptInfo(sourceFile);
		info.setCompileErrors(true);

		if (!doCompile(sourceFile, writer)) {
			writer.flush(); // force any error messages out
			throw new ClassNotFoundException("Unable to compile class: " + sourceFile.getName());
		}

		compileParentClasses(sourceFile, writer);

		forceClassReload();

		info.setCompileErrors(false);
		writer.println("Successfully compiled: " + sourceFile.getName());

		return true;
	}

	private boolean doCompile(ResourceFile sourceFile, final PrintWriter writer) {

		JavaCompiler javaCompiler = ToolProvider.getSystemJavaCompiler();
		if (javaCompiler == null) {
			String message =
				"Compile failed: java compiler provider not found (you must be using a JDK " +
					"to compile scripts)!";
			writer.println(message);
			Msg.error(this, message); // the writer may not be the same as Msg, so log it too
			return false;
		}

		JavaFileManager fileManager =
			new ResourceFileJavaFileManager(GhidraScriptUtil.getScriptSourceDirectories());

		List<ResourceFileJavaFileObject> list = new ArrayList<>();
		list.add(
			new ResourceFileJavaFileObject(sourceFile.getParentFile(), sourceFile, Kind.SOURCE));

		String outputDirectory =
			GhidraScriptUtil.getScriptCompileOutputDirectory(sourceFile).getAbsolutePath();
		Msg.trace(this, "Compiling script " + sourceFile + " to dir " + outputDirectory);

		List<String> options = new ArrayList<>();
		options.add("-g");
		options.add("-d");
		options.add(outputDirectory);
		options.add("-sourcepath");
		options.add(getSourcePath());
		options.add("-classpath");
		options.add(getClassPath());
		options.add("-proc:none"); // Prevents warning when script imports something that will get compiled

		CompilationTask task = javaCompiler.getTask(writer, fileManager, null, options, null, list);
		return task.call();
	}

	private List<Class<?>> getParentClasses(ResourceFile scriptSourceFile) {

		Class<?> scriptClass = getScriptClass(scriptSourceFile);
		if (scriptClass == null) {
			return null; // special signal that there was a problem
		}

		List<Class<?>> parentClasses = new ArrayList<>();
		Class<?> superClass = scriptClass.getSuperclass();
		while (superClass != null) {
			if (superClass.equals(GhidraScript.class)) {
				break; // not interested in the built-in classes
			}
			else if (superClass.equals(HeadlessScript.class)) {
				break; // not interested in the built-in classes
			}
			parentClasses.add(superClass);
			superClass = superClass.getSuperclass();
		}
		return parentClasses;
	}

	private Class<?> getScriptClass(ResourceFile scriptSourceFile) {
		String clazzName = GhidraScriptUtil.getBaseName(scriptSourceFile);
		try {
			return Class.forName(clazzName, true, new JavaScriptClassLoader());
		}
		catch (NoClassDefFoundError | ClassNotFoundException e) {
			Msg.error(this, "Unable to find class file for script file: " + scriptSourceFile, e);
		}
		catch (GhidraScriptUnsupportedClassVersionError e) {
			// Unusual Code Alert!: This implies the script was compiled in a newer
			// version of Java.  So, just delete the class file and try again.
			ResourceFile classFile = e.getClassFile();
			classFile.delete();
			return null; // trigger re-compile
		}
		return null;
	}

	private void compileParentClasses(ResourceFile sourceFile, PrintWriter writer) {

		List<Class<?>> parentClasses = getParentClasses(sourceFile);
		if (parentClasses == null) {
			// this shouldn't happen, as this method is called after the child class is
			// re-compiled and thus, all parent classes should still be there.
			return;
		}

		if (parentClasses.isEmpty()) {
			// nothing to do--no parent class to re-compile
			return;
		}

		//
		// re-compile each class's source file
		//

		// first, reverse the order, so that we compile the highest-level classes first,
		// and then on down, all the way to the script class
		Collections.reverse(parentClasses);

		// next, add back to the list the script that was just compiled, as it may need
		// to be re-compiled after the parent classes are re-compiled
		Class<?> scriptClass = getScriptClass(sourceFile);
		if (scriptClass == null) {
			// shouldn't happen
			return;
		}
		parentClasses.add(scriptClass);

		for (Class<?> parentClass : parentClasses) {
			ResourceFile parentFile = getSourceFile(parentClass);
			if (parentFile == null) {
				continue; // not sure if this can happen (inner-class, maybe?)
			}

			if (!doCompile(parentFile, writer)) {
				Msg.error(this, "Failed to re-compile parent class: " + parentClass);
				return;
			}
		}
	}

	private ResourceFile getSourceFile(Class<?> c) {
		// check all script paths for a dir named
		String classname = c.getName();
		String filename = classname.replace('.', '/') + ".java";

		List<ResourceFile> scriptDirs = GhidraScriptUtil.getScriptSourceDirectories();
		for (ResourceFile dir : scriptDirs) {
			ResourceFile possibleFile = new ResourceFile(dir, filename);
			if (possibleFile.exists()) {
				return possibleFile;
			}
		}

		return null;
	}

	private String getSourcePath() {
		String classpath = System.getProperty("java.class.path");
		List<ResourceFile> dirs = GhidraScriptUtil.getScriptSourceDirectories();
		for (ResourceFile dir : dirs) {
			classpath += (System.getProperty("path.separator") + dir.getAbsolutePath());
		}
		return classpath;
	}

	private String getClassPath() {
		String classpath = System.getProperty("java.class.path");
		List<ResourceFile> dirs = GhidraScriptUtil.getScriptBinDirectories();
		for (ResourceFile dir : dirs) {
			classpath += (System.getProperty("path.separator") + dir.getAbsolutePath());
		}
		return classpath;
	}

	@Override
	public void createNewScript(ResourceFile newScript, String category) throws IOException {
		String scriptName = newScript.getName();
		String className = scriptName;
		int dotpos = scriptName.lastIndexOf('.');
		if (dotpos >= 0) {
			className = scriptName.substring(0, dotpos);
		}
		PrintWriter writer = new PrintWriter(new FileWriter(newScript.getFile(false)));

		writeHeader(writer, category);

		writer.println("import ghidra.app.script.GhidraScript;");

		for (Package pkg : Package.getPackages()) {
			if (pkg.getName().startsWith("ghidra.program.model.")) {
				writer.println("import " + pkg.getName() + ".*;");
			}
		}

		writer.println("");

		writer.println("public class " + className + " extends GhidraScript {");
		writer.println("");

		writer.println("    public void run() throws Exception {");

		writeBody(writer);

		writer.println("    }");
		writer.println("");
		writer.println("}");
		writer.close();
	}

	@Override
	public String getCommentCharacter() {
		return "//";
	}
}
