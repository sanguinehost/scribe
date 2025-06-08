import { getContext, setContext } from 'svelte';

export class SidebarStore {
	activeTab = $state<'characters' | 'personas' | 'lorebooks'>('characters');

	setActiveTab(tab: 'characters' | 'personas' | 'lorebooks') {
		this.activeTab = tab;
	}

	static fromContext(): SidebarStore {
		const store = getContext<SidebarStore>('sidebarStore');
		if (!store) {
			throw new Error('SidebarStore not found in context');
		}
		return store;
	}

	static toContext(store: SidebarStore): SidebarStore {
		setContext('sidebarStore', store);
		return store;
	}
}