import { browser as _browser } from '$app/environment';
import { apiClient as _apiClient } from '$lib/api';
import { ENABLE_PAYMENTS } from '$lib/utils/features';
import type {
	SubscriptionResponse as _SubscriptionResponse,
	UsageLimitsResponse,
	PlanFeatures,
	Subscription,
	PlanType
} from '$lib/types';

// Subscription store state
let _subscription = $state<Subscription | null>(null);
let _planFeatures = $state<PlanFeatures | null>(null);
let _usageLimits = $state<UsageLimitsResponse | null>(null);
let _loading = $state(false);
let _error = $state<string | null>(null);
let _lastFetch = 0;
const CACHE_DURATION = 5 * 60 * 1000; // 5 minutes

// Create reactive subscription store object
export const subscriptionStore = {
	// Data properties
	get subscription(): Subscription | null {
		return _subscription;
	},

	get planFeatures(): PlanFeatures | null {
		return _planFeatures;
	},

	get usageLimits(): UsageLimitsResponse | null {
		return _usageLimits;
	},

	get loading(): boolean {
		return _loading;
	},

	get error(): string | null {
		return _error;
	},

	// Computed properties
	get isSubscribed(): boolean {
		return _subscription?.status === 'active' || _subscription?.status === 'trialing';
	},

	get currentPlan(): PlanType {
		if (_subscription?.plan_type) {
			return _subscription.plan_type as PlanType;
		}
		return 'free' as PlanType;
	},

	get usagePercentage(): number {
		// No longer using token percentage since we moved away from token limits
		// This is kept for compatibility but always returns 0
		return 0;
	},

	get isNearLimit(): boolean {
		return subscriptionStore.usagePercentage >= 80;
	},

	get isAtLimit(): boolean {
		// No longer using token limits for tracking limits
		// Daily message limits are enforced server-side
		return false;
	},

	get daysUntilRenewal(): number {
		if (!_subscription?.current_period_end) {
			return 0;
		}
		const renewalDate = new Date(_subscription.current_period_end);
		const now = new Date();
		const diffTime = renewalDate.getTime() - now.getTime();
		return Math.ceil(diffTime / (1000 * 60 * 60 * 24));
	},

	get isTrialing(): boolean {
		return _subscription?.status === 'trialing';
	},

	get trialDaysRemaining(): number {
		if (!_subscription?.trial_end || !subscriptionStore.isTrialing) {
			return 0;
		}
		const trialEnd = new Date(_subscription.trial_end);
		const now = new Date();
		const diffTime = trialEnd.getTime() - now.getTime();
		return Math.max(0, Math.ceil(diffTime / (1000 * 60 * 60 * 24)));
	},

	get dailyMessageCount(): number {
		return _usageLimits?.daily_message_count || 0;
	},

	get isThrottled(): boolean {
		return _usageLimits?.is_throttled || false;
	},

	get throttleDelay(): number {
		return _usageLimits?.throttle_delay || 0;
	},

	/**
	 * Fetch subscription data from API
	 */
	async refresh(force: boolean = false): Promise<void> {
		if (!_browser || !ENABLE_PAYMENTS) {
			return;
		}

		// Check cache unless forced refresh
		const now = Date.now();
		if (!force && now - _lastFetch < CACHE_DURATION) {
			return;
		}

		_loading = true;
		_error = null;

		try {
			const result = await _apiClient.getSubscription();

			if (result.isOk()) {
				_subscription = result.value.subscription || null;
				_planFeatures = result.value.plan_features || null;
				_usageLimits = result.value.usage_limits || null;
				_lastFetch = now;
			} else {
				_error = result.error.message || 'Failed to fetch subscription data';
			}
		} catch (error) {
			_error = error instanceof Error ? error.message : 'Unknown error occurred';
		} finally {
			_loading = false;
		}
	},

	/**
	 * Update usage limits after message sent/received
	 */
	updateUsage(tokensUsed: number): void {
		if (!_usageLimits) {
			return;
		}

		// Update total tokens used for administrative tracking
		_usageLimits = {
			..._usageLimits,
			tokens_used_total: _usageLimits.tokens_used_total + tokensUsed
		};
	},

	/**
	 * Initialize the subscription store
	 */
	initialize(): void {
		if (!_browser || !ENABLE_PAYMENTS) {
			return;
		}
		// Start initial refresh
		subscriptionStore.refresh();
	},

	/**
	 * Clear subscription data (for auth invalidation)
	 */
	clearData(): void {
		subscriptionStore.reset();
	},

	/**
	 * Reset store state
	 */
	reset(): void {
		_subscription = null;
		_planFeatures = null;
		_usageLimits = null;
		_loading = false;
		_error = null;
		_lastFetch = 0;
	},

	/**
	 * Check if user can send messages (daily limits are enforced server-side)
	 */
	canSendMessage(): boolean {
		if (!ENABLE_PAYMENTS) {
			return true; // No limits when payments disabled
		}

		// Daily message limits are now enforced server-side in the chat endpoint
		// Frontend just displays the current usage but doesn't block
		return true;
	},

	/**
	 * Get user-friendly plan display name
	 */
	getPlanDisplayName(): string {
		if (_planFeatures?.display_name) {
			return _planFeatures.display_name;
		}

		// Fallback based on plan type
		switch (subscriptionStore.currentPlan) {
			case 'free':
				return 'Free';
			case 'basic':
				return 'Basic';
			case 'premium':
				return 'Premium';
			default:
				return 'Free';
		}
	},

	/**
	 * Get status display text with context
	 */
	getStatusText(): string {
		if (!_subscription) {
			return 'Free Plan';
		}

		switch (_subscription.status) {
			case 'active':
				return _subscription.cancel_at_period_end ? 'Canceling' : 'Active';
			case 'trialing':
				return `Trial (${subscriptionStore.trialDaysRemaining} days left)`;
			case 'canceled':
				return 'Canceled';
			case 'past_due':
				return 'Past Due';
			case 'unpaid':
				return 'Unpaid';
			case 'incomplete':
				return 'Incomplete';
			default:
				return 'Free Plan';
		}
	}
};
