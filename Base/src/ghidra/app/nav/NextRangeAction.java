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
package ghidra.app.nav;

import ghidra.app.context.*;
import ghidra.app.plugin.core.navigation.NavigationOptions;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.util.ProgramSelection;

import java.util.Set;

public abstract class NextRangeAction extends NavigatableContextAction {

	private PluginTool tool;
	private NavigationOptions navOptions;

	public NextRangeAction(PluginTool tool, String name, String owner, NavigationOptions navOptions) {
		super(name, owner);
		this.tool = tool;
		this.navOptions = navOptions;
		setEnabled(false);
	}

	@Override
	protected boolean isValidContext(NavigatableActionContext context) {
		//
		// We want the nav actions to work in the current view that supports this, which right 
		// now is the ListingActionContext.  If the current context does not support that, then 
		// we will be called later with the global context, which does support navigation.
		//
		return context instanceof ListingActionContext;
	}

	@Override
	public boolean isEnabledForContext(NavigatableActionContext context) {
		Address currentAddress = context.getAddress();
		ListingActionContext listingContext = (ListingActionContext) context;
		ProgramSelection selection = getSelection(listingContext);
		if (selection == null || selection.isEmpty() || currentAddress == null) {
			return false;
		}

		CodeUnit cu = listingContext.getProgram().getListing().getCodeUnitAt(currentAddress);
		if (cu != null) {
			currentAddress = cu.getMaxAddress();
		}

		AddressRange lastRange = selection.getLastRange();
		Address maxAddress =
			navOptions.isGotoTopAndBottomOfRangeEnabled() ? lastRange.getMaxAddress()
					: lastRange.getMinAddress();
		return currentAddress.compareTo(maxAddress) < 0;
	}

	@Override
	public void actionPerformed(NavigatableActionContext context) {
		// Note: we verified above that the context we are grabbing here is the correct type
		ListingActionContext listingContext = (ListingActionContext) context;

		Address goToAddress = getGoToAddress(listingContext);
		GoToService service = tool.getService(GoToService.class);
		if (service != null) {
			service.goTo(listingContext.getNavigatable(), goToAddress);
		}
	}

	private Address getGoToAddress(ProgramLocationActionContext context) {
		ProgramSelection selection = getSelection(context);
		Address currentAddress = context.getAddress();
		Address maxAddress = currentAddress;

		CodeUnit cu = context.getCodeUnit();
		if (cu != null) {
			maxAddress = cu.getMaxAddress();
		}
		AddressRangeIterator it = selection.getAddressRanges(currentAddress, true);
		if (!it.hasNext()) {
			return currentAddress;   // no next address, just return current address - should never hit this
		}
		AddressRange range = it.next();
		if (range.contains(currentAddress)) {
			if (navOptions.isGotoTopAndBottomOfRangeEnabled()) {
				if (!currentAddress.equals(range.getMaxAddress()) &&
					!maxAddress.equals(range.getMaxAddress())) {
					return range.getMaxAddress();
				}
			}
			if (!it.hasNext()) {
				return currentAddress;
			}
			range = it.next();
		}

		return range.getMinAddress();

	}

	abstract protected ProgramSelection getSelection(ProgramLocationActionContext context);

	@Override
	public boolean shouldAddToWindow(boolean isMainWindow, Set<Class<?>> contextTypes) {
		for (Class<?> class1 : contextTypes) {
			if (NavigatableRangeActionContext.class.isAssignableFrom(class1)) {
				return true;
			}
		}
		return false;
	}
}
