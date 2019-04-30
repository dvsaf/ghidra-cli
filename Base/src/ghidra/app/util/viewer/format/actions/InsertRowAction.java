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
package ghidra.app.util.viewer.format.actions;

import ghidra.app.util.HelpTopics;
import ghidra.app.util.viewer.format.FieldHeader;
import ghidra.app.util.viewer.format.FieldHeaderLocation;
import ghidra.util.HelpLocation;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;


/**
 * Action class that inserts a new row into a FieldModel.
 */
public class InsertRowAction extends DockingAction {
	private FieldHeaderLocation loc;
	private FieldHeader panel;
	
    public InsertRowAction(String owner, FieldHeader panel) {
        super("Insert Row", owner, false);
        this.panel = panel;

        setPopupMenuData( new MenuData( new String[] {"Insert Row"},null,"field" ) );
        setEnabled(true);
		setHelpLocation(new HelpLocation(HelpTopics.CODE_BROWSER, "Insert Row"));
    }
    
    /**
     * @see docking.DockingAction#isEnabledForContext(java.lang.Object)
     */
    @Override
    public boolean isEnabledForContext(ActionContext context) {
    	Object contextObject = context.getContextObject();
		if (contextObject instanceof FieldHeaderLocation) {
			loc = (FieldHeaderLocation)contextObject;
			if (loc.getRow() < loc.getModel().getNumRows()) {
				return true;
			}
		}
		return false;
	}

    /**
     * Method called when the action is invoked.
     */
    @Override
    public void actionPerformed(ActionContext context) {
    	panel.setTabLock( true );
		loc.getModel().addRow(loc.getRow());
		panel.getHeaderTab().update();
    }

}

