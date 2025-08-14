import { Select as SelectPrimitive } from 'bits-ui';

import Label from './select-label.svelte';
import Item from './select-item.svelte';
import Content from './select-content.svelte';
import Trigger from './select-trigger.svelte';
import Separator from './select-separator.svelte';

const Root = SelectPrimitive.Root;
const Group = SelectPrimitive.Group;

export {
	Root,
	Group,
	Label,
	Item,
	Content,
	Trigger,
	Separator,
	//
	Root as Select,
	Group as SelectGroup,
	Label as SelectLabel,
	Item as SelectItem,
	Content as SelectContent,
	Trigger as SelectTrigger,
	Separator as SelectSeparator
};
