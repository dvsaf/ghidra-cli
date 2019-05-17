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
package ghidra.app.plugin.core.calltree;

import java.util.ArrayList;
import java.util.List;

import javax.swing.Icon;

import docking.ActionContext;
import docking.action.*;
import ghidra.app.CorePluginPackage;
import ghidra.app.context.ListingActionContext;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;
import resources.Icons;
import resources.ResourceManager;

/**
 * Assuming a function <b>foo</b>, this plugin will show all callers of <b>foo</b> and all 
 * calls to other functions made by <b>foo</b>. 
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.GRAPH,
	shortDescription = "Call Trees Plugin",
	description = "This plugin shows incoming and outging calls for a give function.  " +
			"More specifically, one tree of the plugin will show all callers of the " +
			"function and the other tree of the plugin will show all calls made " +
			"by the function"
)
//@formatter:on
public class CallTreePlugin extends ProgramPlugin {

	static final Icon PROVIDER_ICON = Icons.ARROW_DOWN_RIGHT_ICON;
	static final Icon FUNCTION_ICON = ResourceManager.loadImage("images/FunctionScope.gif");
	static final Icon RECURSIVE_ICON =
		ResourceManager.loadImage("images/arrow_rotate_clockwise.png");

	private List<CallTreeProvider> providers = new ArrayList<>();
	private DockingAction showProviderAction;

	public CallTreePlugin(PluginTool tool) {
		super(tool, true, false, false);

		createActions();
	}

	@Override
	protected void locationChanged(ProgramLocation loc) {
		for (CallTreeProvider provider : providers) {
			provider.setLocation(loc);
		}
	}

	@Override
	protected void programActivated(Program program) {
		for (CallTreeProvider provider : providers) {
			provider.programActivated(program);
		}
	}

	@Override
	protected void programDeactivated(Program program) {
		for (CallTreeProvider provider : providers) {
			provider.programDeactivated(program);
		}
	}

	@Override
	protected void programClosed(Program program) {
		for (CallTreeProvider provider : providers) {
			provider.programClosed(program);
		}
	}

	@Override
	protected void dispose() {
		List<CallTreeProvider> copy = new ArrayList<>(providers);
		for (CallTreeProvider provider : copy) {
			removeProvider(provider);
		}
	}

	private CallTreeProvider findProviderForLocation(ProgramLocation location) {
		for (CallTreeProvider provider : providers) {
			if (provider.isShowingLocation(location)) {
				return provider;
			}
		}
		return null;
	}

	private void createActions() {
		showProviderAction = new DockingAction("Show Function Call Trees", getName()) {

			@Override
			public void actionPerformed(ActionContext context) {
				showOrCreateNewCallTree(currentLocation);
			}

			@Override
			public boolean isAddToPopup(ActionContext context) {
				return (context instanceof ListingActionContext);
			}
		};
		showProviderAction.setPopupMenuData(new MenuData(
			new String[] { "References", "Show Call Trees" }, PROVIDER_ICON, "ShowReferencesTo"));
		showProviderAction.setToolBarData(new ToolBarData(PROVIDER_ICON, "View"));
		showProviderAction.setHelpLocation(new HelpLocation("CallTreePlugin", "Call_Tree_Plugin"));
		tool.addAction(showProviderAction);
	}

	private void creatAndShowProvider() {
		CallTreeProvider provider = new CallTreeProvider(this);
		providers.add(provider);
		provider.initialize(currentProgram, currentLocation);
		tool.showComponentProvider(provider, true);
	}

	ProgramLocation getCurrentLocation() {
		return currentLocation;
	}

	void removeProvider(CallTreeProvider provider) {
		if (!providers.contains(provider)) {
			// already been removed (this sometimes happens twice, as this happens when providers
			// are closed by the user and when they are removed from the tool due to disposal)
			return;
		}

		providers.remove(provider);
		tool.removeComponentProvider(provider);
		provider.dispose();
	}

	void showOrCreateNewCallTree(ProgramLocation location) {
		if (currentProgram == null) {
			return; // no program; cannot show tool
		}

		CallTreeProvider provider = findProviderForLocation(location);
		if (provider != null) {
			tool.showComponentProvider(provider, true);
			return;
		}

		Function function = getFunction(location);
		if (function == null) {
			tool.setStatusInfo("No function containing address: " + location.getAddress(), true);
			return;
		}

		creatAndShowProvider();
	}

	Function getFunction(ProgramLocation location) {
		FunctionManager functionManager = currentProgram.getFunctionManager();
		Address address = location.getAddress();
		Function function = functionManager.getFunctionContaining(address);
		function = resolveFunction(function, address);
		return function;
	}

	/**
	 *  
	 * Apparently, we create fake function markup for external functions.  Thus, there is no
	 * real function at that address and our plugin has to do some work to find out where
	 * we 'hang' references to the external function, which is itself a Function.  These 
	 * fake function will usually just be a pointer to another function.
	 * 
	 * @param function the function to resolve; if it is not null, then it will be used
	 * @param address the address for which to find a function
	 * @return either the given function if non-null, or a function being referenced from the
	 *         given address.
	 */
	Function resolveFunction(Function function, Address address) {
		if (function != null) {
			return function;
		}

		// maybe we point to another function?
		FunctionManager functionManager = currentProgram.getFunctionManager();
		ReferenceManager referenceManager = currentProgram.getReferenceManager();
		Reference[] references = referenceManager.getReferencesFrom(address);
		for (Reference reference : references) {
			Address toAddress = reference.getToAddress();
			Function toFunction = functionManager.getFunctionAt(toAddress);
			if (toFunction != null) {
				return toFunction;
			}
		}

		return null;
	}
}
