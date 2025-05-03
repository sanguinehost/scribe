import { expect, test } from '@playwright/test';

test('root path redirects to login when unauthenticated', async ({ page }) => {
	await page.goto('/');
	// Wait for the redirection to complete and check the URL
	await page.waitForURL('**/login');
	await expect(page).toHaveURL(/.*\/login/);
	// Optionally, check for an element on the login page to confirm it loaded
	await expect(page.getByRole('heading', { name: 'Login' })).toBeVisible();
});
