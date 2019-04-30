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
package ghidra.app.plugin.core.calltree;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.util.ProgramLocation;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

import javax.swing.tree.TreePath;

import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.GTreeSlowLoadingNode;
import docking.widgets.tree.support.GTreeFilter;

public abstract class CallNode extends GTreeSlowLoadingNode {

	private boolean allowDuplicates;
	protected AtomicInteger filterDepth;
	private int depth = -1;

	/** Used to signal that this node has been marked for replacement */
	protected boolean invalid = false;

	public CallNode(AtomicInteger filterDepth) {
		this.filterDepth = filterDepth;
	}

	public abstract Function getContainingFunction();

	/**
	 * Returns a location that represents the caller of the callee.
	 */
	public abstract ProgramLocation getLocation();

	/**
	 * Returns the address that for the caller of the callee.
	 */
	public abstract Address getSourceAddress();

	/**
	 * Called when this node needs to be reconstructed due to external changes, such as when 
	 * functions are renamed. 
	 * 
	 * @return a new node that is the same type as 'this' node.
	 */
	abstract CallNode recreate();

	protected Set<Reference> getReferencesFrom(Program program, AddressSetView addresses,
			TaskMonitor monitor) throws CancelledException {
		Set<Reference> set = new HashSet<Reference>();
		ReferenceManager referenceManager = program.getReferenceManager();
		AddressIterator addressIterator = addresses.getAddresses(true);
		while (addressIterator.hasNext()) {
			monitor.checkCanceled();
			Address address = addressIterator.next();
			Reference[] referencesFrom = referenceManager.getReferencesFrom(address);
			if (referencesFrom != null) {
				for (Reference reference : referencesFrom) {
					set.add(reference);
				}
			}
		}
		return set;
	}

	/**
	 * Signals that this node should not override the equals method to treat all nodes with the
	 * same name as the same.  When the user wants to see duplicates, each node should rely on
	 * Java's default notion of equality; otherwise, the JTree goes out to lunch.
	 */
	protected void setAllowsDuplicates(boolean allowDuplicates) {
		this.allowDuplicates = allowDuplicates;
	}

	@Override
	public boolean equals(Object other) {
		if (allowDuplicates) {
			return super.equals(other);
		}

		if (other == this) {
			return true;
		}

		if (other == null) {
			return false;
		}

		if (!getClass().equals(other.getClass())) {
			return false;
		}

		CallNode otherCallNode = (CallNode) other;
		return getName().equals(otherCallNode.getName());
	}

	protected class CallNodeComparator implements Comparator<GTreeNode> {
		@Override
		public int compare(GTreeNode o1, GTreeNode o2) {
			return ((CallNode) o1).getSourceAddress().compareTo(((CallNode) o2).getSourceAddress());
		}
	}

	@Override
	public void filter(GTreeFilter filter, TaskMonitor monitor, int min, int max)
			throws CancelledException {
		if (depth() > filterDepth.get()) {
			doSetActiveChildren(new ArrayList<GTreeNode>());
			return;
		}
		super.filter(filter, monitor, min, max);
	}

	private int depth() {
		if (depth < 0) {
			TreePath treePath = getTreePath();
			Object[] path = treePath.getPath();
			depth = path.length;
		}
		return depth;
	}

	boolean functionIsInPath() {
		TreePath path = getTreePath();
		Object[] pathComponents = path.getPath();
		for (Object pathComponent : pathComponents) {
			CallNode node = (CallNode) pathComponent;
			Function nodeFunction = node.getContainingFunction();
			Function myFunction = getContainingFunction();
			if (node != this && nodeFunction.equals(myFunction)) {
				return true;
			}
		}
		return false;
	}
}
