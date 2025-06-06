import { readable } from 'svelte/store';

export const page = readable({
    url: new URL('http://localhost:3000/'),
    params: {},
    route: {
        id: null
    },
    status: 200,
    error: null,
    data: {}
});