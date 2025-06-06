export class Box<T> {
	value = $state<T>() as T;

	constructor(value: T) {
		this.value = value;
	}
}
