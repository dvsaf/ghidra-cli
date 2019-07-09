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
package pecoffcli;

import java.io.IOException;
import java.math.BigInteger;
import java.util.List;

import generic.continues.GenericFactory;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.bin.format.pe.COMDescriptorDataDirectory;
import ghidra.app.util.bin.format.pe.OptionalHeader;
import ghidra.app.util.bin.format.pe.PeUtils;
import ghidra.app.util.bin.format.pe.PortableExecutable;
import ghidra.app.util.bin.format.pe.PortableExecutable.SectionLayout;
import ghidra.app.util.bin.format.pe.cli.methods.CliMethodDef;
import ghidra.app.util.bin.format.pe.cli.tables.CliAbstractTableRow;
import ghidra.app.util.bin.format.pe.cli.tables.CliTableMethodDef;
import ghidra.app.util.bin.format.pe.cli.tables.CliTypeTable;
import ghidra.app.util.bin.format.pe.cli.tables.CliTableMethodDef.CliMethodDefRow;
import ghidra.app.util.importer.MemoryConflictHandler;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.importer.MessageLogContinuesFactory;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader;
import ghidra.app.util.opinion.PeLoader;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class PeCliLoader extends PeLoader {

	/** The name of the PECLI loader */
	public final static String PECLI_NAME = "Portable Executable with CLI";

	@Override
	public String getName() {

		// TODO: Name the loader. This name must match the name of the loader in the
		// .opinion files.

		return PECLI_NAME;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program,
			MemoryConflictHandler handler, TaskMonitor monitor, MessageLog log) throws IOException {

		// Need to parse CLI headers
		options.add(new Option(PARSE_CLI_HEADERS_OPTION_NAME, true, Boolean.class,
				Loader.COMMAND_LINE_ARG_PREFIX + "-parseCliHeaders"));
		super.load(provider, loadSpec, options, program, handler, monitor, log);

		monitor.setMessage(program.getName() + ": Setting mode flag for managed methods");

		GenericFactory factory = MessageLogContinuesFactory.create(log);
		PortableExecutable pe = PortableExecutable.createPortableExecutable(factory, provider, SectionLayout.FILE,
				true, true);
		if (pe.getNTHeader().getOptionalHeader().isCLI()) {

			var corDir = (COMDescriptorDataDirectory) pe.getNTHeader().getOptionalHeader()
					.getDataDirectories()[OptionalHeader.IMAGE_DIRECTORY_ENTRY_COMHEADER];

			var metadataRoot = corDir.getHeader().getMetadata().getMetadataRoot();
			var methodsTable = metadataRoot.getMetadataStream().getTable(CliTypeTable.MethodDef);
			for (var index = 1; index <= methodsTable.getNumRows(); index++) {
				var method = ((CliTableMethodDef.CliMethodDefRow) methodsTable.getRow(index));
				if (method.RVA == 0)
					continue;
				Address addr = PeUtils.getMarkupAddress(program, false, pe.getNTHeader(), method.RVA);
				// Create MethodDef at RVA
				BinaryReader reader =
					new BinaryReader(new MemoryByteProvider(program.getMemory(), addr),
						!program.getMemory().isBigEndian());
				CliMethodDef methodDef = new CliMethodDef(addr, reader);
				Address startAddr = addr.add(methodDef.isFatHeader() ? 12 : 1);
				Address endAddr = startAddr.add(methodDef.getMethodSize() - 1); // TODO: -1? AddressSetView is inclusive.
				// set cliMode flag
				var context = program.getProgramContext();
				var register = context.getRegister("cliMode");
				var registerValue = new RegisterValue(register, BigInteger.ONE, BigInteger.ONE);
				try {
					context.setRegisterValue(startAddr, endAddr, registerValue);
				} catch (ContextChangeException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}

		monitor.setMessage(program.getName() + ": done!");
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec, DomainObject domainObject,
			boolean isLoadIntoProgram) {
		List<Option> list = super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		// TODO: If this loader has custom options, add them to 'list'
//		list.add(new Option("Option name goes here", "Default option value goes here"));

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options) {

		// TODO: If this loader has custom options, validate them here. Not all options
		// require
		// validation.

		return super.validateOptions(provider, loadSpec, options);
	}
}
