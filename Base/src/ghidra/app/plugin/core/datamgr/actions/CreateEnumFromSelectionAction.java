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
package ghidra.app.plugin.core.datamgr.actions;

import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.DataTypesActionContext;
import ghidra.app.plugin.core.datamgr.archive.SourceArchive;
import ghidra.app.plugin.core.datamgr.tree.DataTypeNode;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.data.ProgramDataTypeManager;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;

import javax.swing.SwingUtilities;
import javax.swing.tree.TreePath;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.dialogs.InputDialog;
import docking.widgets.tree.*;

public class CreateEnumFromSelectionAction extends DockingAction {
	private final DataTypeManagerPlugin plugin;

	public CreateEnumFromSelectionAction(DataTypeManagerPlugin plugin) {
		super("Enum from Selection", plugin.getName());
		this.plugin = plugin;

		setPopupMenuData(new MenuData(new String[] { "Create Enum From Selection" }, null, "Edit"));
		setHelpLocation(new HelpLocation("DataTypeManagerPlugin", "CreateEnumFromSelection"));
		setEnabled(true);
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		if (!(context instanceof DataTypesActionContext)) {
			return false;
		}

		GTree gtree = (GTree) context.getContextObject();
		TreePath[] selectionPaths = gtree.getSelectionPaths();
		if (selectionPaths == null || selectionPaths.length <= 1) {
			return false;
		}

		return !containsInvalidNodes(selectionPaths);
	}

	@Override
	public void actionPerformed(ActionContext context) {

		//Get the selected enums 
		final GTree gTree = (GTree) context.getContextObject();
		TreePath[] paths = gTree.getSelectionPaths();
		Enum[] enumArray = new Enum[paths.length];
		int i = 0;

		for (TreePath element : paths) {
			GTreeNode node = (GTreeNode) element.getLastPathComponent();
			DataTypeNode dataTypeNode = (DataTypeNode) node;
			enumArray[i++] = (Enum) dataTypeNode.getDataType();
		}
		Category category = null;
		DataTypeManager[] dataTypeManagers = plugin.getDataTypeManagers();
		DataTypeManager myDataTypeManager = null;
		for (DataTypeManager dataTypeManager : dataTypeManagers) {
			if (dataTypeManager instanceof ProgramDataTypeManager) {
				myDataTypeManager = dataTypeManager;
				category = myDataTypeManager.getCategory(new CategoryPath("/"));
				if (category == null) {
					Msg.error(this, "Could not find program data type manager");
					return;
				}

			}
		}

		String newName = "";
		PluginTool tool = plugin.getTool();

		while (newName.equals("")) {
			InputDialog inputDialog =
				new InputDialog("Name new ENUM", "Please enter a name for the new ENUM: ");
			tool = plugin.getTool();
			tool.showDialog(inputDialog);

			if (inputDialog.isCanceled()) {
				return;
			}
			newName = inputDialog.getValue();
		}

		DataType dt = myDataTypeManager.getDataType(category.getCategoryPath(), newName);
		while (dt != null) {
			InputDialog dupInputDialog =
				new InputDialog("Duplicate ENUM Name",
					"Please enter a unique name for the new ENUM: ");
			tool = plugin.getTool();
			tool.showDialog(dupInputDialog);

			if (dupInputDialog.isCanceled()) {
				return;
			}
			newName = dupInputDialog.getValue();
			dt = myDataTypeManager.getDataType(category.getCategoryPath(), newName);
		}
		createNewEnum(category, enumArray, newName);

		// select new node in tree.  Must use invoke later to give the tree a chance to add the
		// the new node to the tree.
		myDataTypeManager.flushEvents();
		final String parentNodeName = myDataTypeManager.getName();
		final String newNodeName = newName;
		SwingUtilities.invokeLater(new Runnable() {
			@Override
			public void run() {
				GTreeRootNode rootNode = gTree.getRootNode();
				gTree.setSelectedNodeByNamePath(new String[] { rootNode.getName(), parentNodeName,
					newNodeName });
			}
		});
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (!(context instanceof DataTypesActionContext)) {
			return false;
		}

		GTree gtree = (GTree) context.getContextObject();
		TreePath[] selectionPaths = gtree.getSelectionPaths();
		if (selectionPaths == null || selectionPaths.length <= 1) {
			return false;
		}

		return !containsInvalidNodes(selectionPaths);
	}

	private boolean containsInvalidNodes(TreePath[] selectionPaths) {

		// determine if all selected nodes are ENUMs, if so, return true, if not, return false
		for (TreePath path : selectionPaths) {
			GTreeNode node = (GTreeNode) path.getLastPathComponent();
			if (!(node instanceof DataTypeNode)) {
				return true;
			}
			DataTypeNode dataTypeNode = (DataTypeNode) node;
			DataType dataType = dataTypeNode.getDataType();
			if (!(dataType instanceof Enum)) {
				return true;
			}
		}
		return false;
	}

	public void createNewEnum(Category category, Enum[] enumArray, String newName) {

		// figure out size of the new enum using the max size of the selected enums
		int maxEnumSize = 1;
		for (int i = 0; i < enumArray.length; i++) {
			if (maxEnumSize < enumArray[i].getLength()) {
				maxEnumSize = enumArray[i].getLength();
			}
		}
		SourceArchive sourceArchive = category.getDataTypeManager().getLocalSourceArchive();
		Enum dataType =
			new EnumDataType(category.getCategoryPath(), newName, maxEnumSize,
				category.getDataTypeManager());

		for (int i = 0; i < enumArray.length; i++) {
			String[] names = enumArray[i].getNames();
			for (int j = 0; j < names.length; j++) {
				dataType.add(names[j], enumArray[i].getValue(names[j]));

			}
		}

		dataType.setSourceArchive(sourceArchive);
		int id = category.getDataTypeManager().startTransaction("Create New Enum Data Type");
		category.getDataTypeManager().addDataType(dataType, DataTypeConflictHandler.REPLACE_HANDLER);
		category.getDataTypeManager().endTransaction(id, true);

	}

}
