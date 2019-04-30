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

import ghidra.util.SystemUtilities;
import ghidra.util.exception.UsrException;

import java.util.Arrays;

import javax.swing.ImageIcon;

import resources.ResourceManager;
import docking.ActionContext;

/**
 * Action for use in the structure data type editor.
 * This action has help associated with it.
 */
public class CreateInternalStructureAction extends CompositeEditorTableAction {

	private final static ImageIcon createInternalStructureIcon =
		ResourceManager.loadImage("images/cstruct.png");
	private final static String ACTION_NAME = "Create Structure From Selection";
	private final static String GROUP_NAME = COMPONENT_ACTION_GROUP;
	private final static String DESCRIPTION =
		"Create a new structure from the selected components and replace them with it.";
	private static String[] popupPath = new String[] { ACTION_NAME };

	public CreateInternalStructureAction(CompositeEditorProvider provider) {
		super(provider, EDIT_ACTION_PREFIX + ACTION_NAME, GROUP_NAME, popupPath, null,
			createInternalStructureIcon);
		setDescription(DESCRIPTION);
		adjustEnablement();
	}

	@Override
	public void actionPerformed(ActionContext context) {
		int[] selectedComponentRows = model.getSelectedComponentRows();
		boolean hasComponentSelection = model.hasComponentSelection();
		boolean contiguousComponentSelection = model.isContiguousComponentSelection();
		if (hasComponentSelection && contiguousComponentSelection &&
			(selectedComponentRows.length > 0)) {
			Arrays.sort(selectedComponentRows);
			int numComponents = model.getNumComponents();
			int maxRow = selectedComponentRows[selectedComponentRows.length - 1];
			if (maxRow < numComponents) {
				try {
					((StructureEditorModel) model).createInternalStructure();
				}
				catch (UsrException e1) {
					model.setStatus(e1.getMessage(), true);
				}
			}
		}
		requestTableFocus();
		SystemUtilities.runSwingLater(new Runnable() {

			@Override
			public void run() {
				provider.toFront();
				provider.requestFocus();
				provider.editorPanel.requestFocus();
				provider.editorPanel.table.requestFocus();
			}
		});
	}

	@Override
	public void adjustEnablement() {
		setEnabled(isCreateInternalStructureAllowed());
	}

	private boolean isCreateInternalStructureAllowed() {
		return model.hasComponentSelection() && model.isContiguousComponentSelection();
	}
}
