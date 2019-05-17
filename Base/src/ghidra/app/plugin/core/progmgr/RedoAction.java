/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.plugin.core.progmgr;

import ghidra.app.context.ProgramActionContext;
import ghidra.app.context.ProgramContextAction;
import ghidra.app.services.GoToService;
import ghidra.app.services.NavigationHistoryService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.ToolConstants;
import ghidra.program.model.listing.Program;
import ghidra.util.*;

import java.awt.event.InputEvent;
import java.io.IOException;

import javax.swing.Icon;

import resources.ResourceManager;
import docking.ActionContext;
import docking.action.*;

public class RedoAction extends ProgramContextAction {
	private final PluginTool tool;

	public RedoAction(PluginTool tool, String owner) {
		super("Redo", owner);
		this.tool = tool;
		setHelpLocation(new HelpLocation("Tool", "Redo"));
		String[] menuPath = { ToolConstants.MENU_EDIT, "&Redo" };
		String group = "Undo";
		Icon icon = ResourceManager.loadImage("images/redo.png");
		MenuData menuData = new MenuData(menuPath, icon, group);
		menuData.setMenuSubGroup("2Redo"); // make this appear below the undo menu item
		setMenuBarData(menuData);
		setToolBarData(new ToolBarData(icon, group));
		setKeyBindingData(new KeyBindingData('Z', InputEvent.CTRL_MASK | InputEvent.SHIFT_MASK));
		setDescription("Redo");
	}

	@Override
	protected void actionPerformed(ProgramActionContext programContext) {
		Program program = programContext.getProgram();
		try {
			saveCurrentLocationToHistory();
			program.redo();
		}
		catch (IOException e) {
			Msg.showError(this, null, null, null, e);
		}
	}

	@Override
	protected boolean isEnabledForContext(ProgramActionContext context) {
		Program program = context.getProgram();
		if (program.canRedo()) {
			String programName = program.getDomainFile().getName();
			getMenuBarData().setMenuItemName("Redo " + programName);
			String tip = HTMLUtilities.toWrappedHTML("Redo " + program.getRedoName());
			setDescription(tip);
			return true;
		}
		return false;
	}

	private void saveCurrentLocationToHistory() {
		GoToService goToService = tool.getService(GoToService.class);
		NavigationHistoryService historyService = tool.getService(NavigationHistoryService.class);
		if (goToService != null && historyService != null) {
			historyService.addNewLocation(goToService.getDefaultNavigatable());
		}
	}

	@Override
	public boolean isEnabledForContext(ActionContext actionContext) {
		if (!super.isEnabledForContext(actionContext)) {
			setDescription("Redo");
			getMenuBarData().setMenuItemName("Redo");
			return false;
		}
		return true;
	}
}
