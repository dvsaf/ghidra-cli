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
package ghidra.app.plugin.core.navigation;

import javax.swing.*;

import docking.action.*;
import ghidra.app.context.ListingActionContext;
import ghidra.app.nav.Navigatable;
import ghidra.app.plugin.core.codebrowser.CodeViewerActionContext;
import ghidra.app.plugin.core.codebrowser.actions.CodeViewerContextAction;
import ghidra.app.services.GoToService;
import ghidra.app.util.HelpTopics;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.ToolConstants;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.AddressFieldLocation;
import ghidra.util.HelpLocation;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.*;

public abstract class AbstractNextPreviousAction extends CodeViewerContextAction {

	private boolean isForward = true;
	private PluginTool tool;

	public AbstractNextPreviousAction(PluginTool tool, String name, String owner, String subGroup) {
		super(name, owner);
		this.tool = tool;

		ToolBarData toolBarData =
			new ToolBarData(getIcon(), ToolConstants.NEXT_CODE_UNIT_NAVIGATION_MENU_GROUP);
		toolBarData.setToolBarSubGroup(subGroup);
		setToolBarData(toolBarData);
		MenuData menuData =
			new MenuData(new String[] { ToolConstants.MENU_NAVIGATION, getMenuName() }, getIcon(),
				ToolConstants.NEXT_CODE_UNIT_NAVIGATION_MENU_GROUP);
		menuData.setMenuSubGroup(subGroup);
		setMenuBarData(menuData);
		setKeyBindingData(new KeyBindingData(getKeyStroke()));
		setHelpLocation(new HelpLocation(HelpTopics.NAVIGATION, name));
		setDescription(getDescriptionString());
	}

	protected abstract Icon getIcon();

	protected abstract KeyStroke getKeyStroke();

	@Override
	public void actionPerformed(final CodeViewerActionContext context) {
		Task t = new Task("Searching for " + getNavigationTypeName() + "...", true, false, true) {
			@Override
			public void run(TaskMonitor monitor) {
				gotoNextPrevious(monitor, context);
			}
		};
		new TaskLauncher(t, tool.getToolFrame(), 500);
	}

	void gotoNextPrevious(TaskMonitor monitor, final CodeViewerActionContext context) {

		try {
			final Address address =
				isForward ? getNextAddress(monitor, context.getProgram(), context.getAddress())
						: getPreviousAddress(monitor, context.getProgram(), context.getAddress());

			SwingUtilities.invokeLater(new Runnable() {
				@Override
				public void run() {
					gotoAddress(context, address);
				}
			});

		}
		catch (CancelledException e) {
		}
	}

	private void gotoAddress(ListingActionContext actionContext, Address address) {
		if (address == null) {
			tool.setStatusInfo("Unable to locate another \"" + getNavigationTypeName() +
				"\" past the current range, in the current direction.");
			return;
		}
		tool.clearStatusInfo();

		GoToService service = tool.getService(GoToService.class);
		if (service != null) {
			Navigatable navigatable = actionContext.getNavigatable();
			gotoAddress(service, navigatable, address);
		}

	}

	protected void gotoAddress(GoToService service, Navigatable navigatable, Address address) {
		Program program = navigatable.getProgram();
		service.goTo(navigatable, new AddressFieldLocation(program, address), program);
	}

	void setDirection(boolean isForward) {
		this.isForward = isForward;
		getMenuBarData().setMenuItemName(getMenuName());
		setDescription(getDescription());
	}

	private String getMenuName() {
		String prefix = isForward ? "Next " : "Previous ";
		return prefix + getNavigationTypeName();
	}

	private String getDescriptionString() {
		String prefix = isForward ? "Go To Next " : "Go To Previous ";
		return prefix + getNavigationTypeName();
	}

	abstract protected String getNavigationTypeName();

	abstract protected Address getNextAddress(TaskMonitor monitor, Program program, Address address)
			throws CancelledException;

	abstract protected Address getPreviousAddress(TaskMonitor monitor, Program program,
			Address address) throws CancelledException;
}
