export class Box<T> {
	value = $state<T>() as T;

	constructor(_value: T) {
		this.value = _value;
	}
}
