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
package ghidra.app.plugin.core.compositeeditor;

import ghidra.app.services.DataTypeManagerService;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;

import docking.ActionContext;

/**
 * Action for use in the composite data type editor.
 * This action has help associated with it.
 */
public class EditComponentAction extends CompositeEditorTableAction {

	private final static String ACTION_NAME = "Edit Component";
	private final static String GROUP_NAME = BASIC_ACTION_GROUP;
	private final static String DESCRIPTION = "Edit the selected component";
	private static String[] popupPath = new String[] { ACTION_NAME + "..." };
	private static String[] menuPath = new String[] { ACTION_NAME + "..." };
	private DataTypeManagerService dtmService;

	/**
	 * @param id
	 * @param group
	 * @param owner
	 * @param popupPath
	 * @param menuPath
	 * @param icon
	 * @param useToolbar
	 * @param checkBox
	 */
	public EditComponentAction(CompositeEditorProvider provider) {
		super(provider, EDIT_ACTION_PREFIX + ACTION_NAME, GROUP_NAME, popupPath, menuPath, null);
		this.dtmService = provider.dtmService;
		setDescription(DESCRIPTION);
		adjustEnablement();
	}

	/* (non-Javadoc)
	 * @see java.awt.event.ActionListener#actionPerformed(java.awt.event.ActionEvent)
	 */
	@Override
	public void actionPerformed(ActionContext context) {
		int row = model.getRow();
		if (row < model.getNumComponents()) {
			DataTypeComponent comp = model.getComponent(row);
			DataType dt = DataTypeHelper.getBaseType(comp.getDataType());
			if ((dt instanceof Structure) || (dt instanceof Union) || (dt instanceof Enum)) {
				DataTypeManager dtm = model.getOriginalDataTypeManager();
				if (dtm != null) {
					dt = dtm.getDataType(dt.getDataTypePath());
					if (dt != null) {
						this.dtmService.edit(dt);
						return;
					}
				}
				String name =
					(dt != null) ? dt.getDisplayName() : comp.getDataType().getDisplayName();
				model.setStatus("Can't edit \"" + name + "\".");
			}
			else {
				model.setStatus("Can only edit a structure, union or enum.");
			}
		}
		requestTableFocus();
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.datamanager.editor.CompositeEditorAction#adjustEnablement()
	 */
	@Override
	public void adjustEnablement() {
		setEnabled(model.isEditComponentAllowed());
	}

}
