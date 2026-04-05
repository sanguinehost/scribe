import prettier from 'eslint-config-prettier';
import js from '@eslint/js';
import { includeIgnoreFile } from '@eslint/compat';
import svelte from 'eslint-plugin-svelte';
import globals from 'globals';
import { fileURLToPath } from 'node:url';
import ts from 'typescript-eslint';
const gitignorePath = fileURLToPath(new URL('./.gitignore', import.meta.url));

export default ts.config(
	{},
	includeIgnoreFile(gitignorePath),
	js.configs.recommended,
	...ts.configs.recommended,
	...svelte.configs['flat/recommended'],
	prettier,
	...svelte.configs['flat/prettier'],
	{
		languageOptions: {
			globals: {
				...globals.browser,
				...globals.node
			}
		}
	},
	{
		files: ['**/*.svelte', '**/*.svelte.ts', '**/*.svelte.js'],

		languageOptions: {
			parserOptions: {
				parser: ts.parser
			}
		},
		rules: {
			'svelte/valid-compile': 'off'
		}
	},
	{
		// Disable custom element props validation for UI components
		files: ['src/lib/components/ui/**/*.svelte'],
		rules: {
			'svelte/valid-compile': 'off'
		}
	},
	{
		rules: {
			'svelte/require-each-key': 'warn',
			'svelte/prefer-svelte-reactivity': 'warn',
			'@typescript-eslint/no-explicit-any': 'warn',
			'no-useless-assignment': 'warn',
			'preserve-caught-error': 'off',
			'svelte/no-navigation-without-resolve': 'warn',
			'svelte/no-immutable-reactive-statements': 'warn',
			'svelte/no-reactive-literals': 'warn',
			'svelte/prefer-writable-derived': 'warn',
			'svelte/no-useless-mustaches': 'warn',
			'svelte/no-dom-manipulating': 'warn',
			'@typescript-eslint/no-unused-vars': [
				'warn',
				{
					args: 'all',
					argsIgnorePattern: '^_',
					caughtErrors: 'all',
					caughtErrorsIgnorePattern: '^_',
					destructuredArrayIgnorePattern: '^_',
					varsIgnorePattern: '^_',
					ignoreRestSiblings: true
				}
			]
		}
	}
);
