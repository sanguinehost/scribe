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
let _customerPortalUrl = $state<string | null>(null);
let _loading = $state(false);
let _error = $state<string | null>(null);
let _lastFetch = 0;
const CACHE_DURATION = 30 * 1000; // 30 seconds

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

	get customerPortalUrl(): string | null {
		return _customerPortalUrl;
	},

	// Computed properties
	get isSubscribed(): boolean {
		if (!_subscription) return false;
		// Only consider active or valid trialing subscriptions
		if (_subscription.status === 'active') return true;
		if (_subscription.status === 'trialing') return true;
		// For pending_cancellation, only if it's still trialing
		if (_subscription.status === 'pending_cancellation' && subscriptionStore.isTrialing) {
			return true;
		}
		return false;
	},

	get currentPlan(): PlanType {
		if (_subscription?.plan_type) {
			// Handle 'pro' -> 'premium' mapping for legacy subscriptions
			const planType = _subscription.plan_type === 'pro' ? 'premium' : _subscription.plan_type;
			console.log('🔧 Plan Type Mapping:', {
				originalPlanType: _subscription.plan_type,
				mappedPlanType: planType,
				subscriptionId: _subscription.id
			});
			return planType as PlanType;
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
		if (!_subscription) {
			console.log('🗓️ [DAYS_UNTIL_RENEWAL] No subscription found, returning 0');
			return 0;
		}

		// For cancelled trials, use trial_end instead of current_period_end
		if (subscriptionStore.isCancelledTrial && _subscription.trial_end) {
			const trialEndDate = new Date(_subscription.trial_end);
			const now = new Date();
			const diffTime = trialEndDate.getTime() - now.getTime();
			const daysUntilRenewal = Math.max(0, Math.ceil(diffTime / (1000 * 60 * 60 * 24)));

			console.log('🗓️ [DAYS_UNTIL_RENEWAL] Cancelled trial calculation:', {
				subscriptionId: _subscription.id,
				status: _subscription.status,
				trialEnd: _subscription.trial_end,
				trialEndParsed: trialEndDate.toISOString(),
				currentTime: now.toISOString(),
				diffTimeMs: diffTime,
				diffTimeDays: diffTime / (1000 * 60 * 60 * 24),
				daysUntilRenewal,
				isCancelledTrial: subscriptionStore.isCancelledTrial
			});

			return daysUntilRenewal;
		}

		// For active trials, also use trial_end
		if (subscriptionStore.isTrialing && _subscription.trial_end) {
			const trialEndDate = new Date(_subscription.trial_end);
			const now = new Date();
			const diffTime = trialEndDate.getTime() - now.getTime();
			const daysUntilRenewal = Math.max(0, Math.ceil(diffTime / (1000 * 60 * 60 * 24)));

			console.log('🗓️ [DAYS_UNTIL_RENEWAL] Active trial calculation:', {
				subscriptionId: _subscription.id,
				status: _subscription.status,
				trialEnd: _subscription.trial_end,
				daysUntilRenewal,
				isTrialing: subscriptionStore.isTrialing
			});

			return daysUntilRenewal;
		}

		// For regular subscriptions, use current_period_end
		if (!_subscription.current_period_end) {
			console.log('🗓️ [DAYS_UNTIL_RENEWAL] No current_period_end found, returning 0');
			return 0;
		}
		const renewalDate = new Date(_subscription.current_period_end);
		const now = new Date();
		const diffTime = renewalDate.getTime() - now.getTime();
		const daysUntilRenewal = Math.ceil(diffTime / (1000 * 60 * 60 * 24));

		console.log('🗓️ [DAYS_UNTIL_RENEWAL] Regular subscription calculation:', {
			subscriptionId: _subscription.id,
			status: _subscription.status,
			currentPeriodEnd: _subscription.current_period_end,
			daysUntilRenewal
		});

		return daysUntilRenewal;
	},

	get isTrialing(): boolean {
		if (!_subscription) return false;
		// A subscription is considered "trialing" if:
		// 1. Status is explicitly "trialing", OR
		// 2. Status is "pending_cancellation" but we have a trial_end date that hasn't passed
		if (_subscription.status === 'trialing') {
			return true;
		}
		if (_subscription.status === 'pending_cancellation' && _subscription.trial_end) {
			const trialEnd = new Date(_subscription.trial_end);
			const now = new Date();
			return now < trialEnd;
		}
		return false;
	},

	get trialDaysRemaining(): number {
		if (
			!_subscription?.trial_end ||
			(!subscriptionStore.isTrialing && !subscriptionStore.isCancelledTrial)
		) {
			return 0;
		}
		const trialEnd = new Date(_subscription.trial_end);
		const now = new Date();
		const diffTime = trialEnd.getTime() - now.getTime();
		const daysRemaining = Math.max(0, Math.ceil(diffTime / (1000 * 60 * 60 * 24)));

		// Debug logging to trace the calculation
		console.log('🗓️ [TRIAL_DAYS] Trial days calculation:', {
			subscriptionId: _subscription.id,
			trialEnd: _subscription.trial_end,
			trialEndParsed: trialEnd.toISOString(),
			currentTime: now.toISOString(),
			diffTimeMs: diffTime,
			diffTimeDays: diffTime / (1000 * 60 * 60 * 24),
			daysRemaining,
			isTrialing: subscriptionStore.isTrialing,
			isCancelledTrial: subscriptionStore.isCancelledTrial
		});

		return daysRemaining;
	},

	get isCancelledTrial(): boolean {
		if (!_subscription) return false;
		// A trial is cancelled if:
		// 1. Status is pending_cancellation with active trial, OR
		// 2. Status is expired/canceled but we still have trial_end date that hasn't passed yet
		if (_subscription.status === 'pending_cancellation' && _subscription.trial_end) {
			const trialEnd = new Date(_subscription.trial_end);
			const now = new Date();
			return now < trialEnd;
		}
		if (_subscription.status === 'canceled' && _subscription.trial_end) {
			const trialEnd = new Date(_subscription.trial_end);
			const now = new Date();
			return now < trialEnd;
		}
		return false;
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
			console.log(
				'🔄 [FRONTEND_SUBSCRIPTION] Skipping refresh: browser=',
				_browser,
				'payments_enabled=',
				ENABLE_PAYMENTS
			);
			return;
		}

		// Check cache unless forced refresh
		const now = Date.now();
		const cacheAge = now - _lastFetch;
		if (!force && cacheAge < CACHE_DURATION) {
			console.log('🔄 [FRONTEND_SUBSCRIPTION] Using cached data:', {
				cacheAge: `${Math.round(cacheAge / 1000)}s`,
				cacheLimit: `${CACHE_DURATION / 1000}s`,
				lastFetch: new Date(_lastFetch).toISOString()
			});
			return;
		}

		console.log('🔄 [FRONTEND_SUBSCRIPTION] Starting subscription refresh:', {
			forced: force,
			cacheAge: `${Math.round(cacheAge / 1000)}s`,
			currentSubscription: _subscription
				? {
						id: _subscription.id,
						status: _subscription.status,
						plan_type: _subscription.plan_type
					}
				: null
		});

		_loading = true;
		_error = null;

		try {
			console.log('🔄 [FRONTEND_SUBSCRIPTION] Calling API...');
			const result = await _apiClient.getSubscription();

			if (result.isOk()) {
				console.log('🔄 [FRONTEND_SUBSCRIPTION] API call SUCCESS - Raw response:', {
					subscription: result.value.subscription,
					plan_features: result.value.plan_features,
					usage_limits: result.value.usage_limits,
					customer_portal_url: result.value.customer_portal_url
				});

				// Log specific details about plan type mapping
				if (result.value.subscription) {
					console.log('🔄 [FRONTEND_SUBSCRIPTION] Subscription details:', {
						id: result.value.subscription.id,
						plan_type: result.value.subscription.plan_type,
						status: result.value.subscription.status,
						paddle_subscription_id: result.value.subscription.paddle_subscription_id,
						current_period_start: result.value.subscription.current_period_start,
						current_period_end: result.value.subscription.current_period_end,
						trial_end: result.value.subscription.trial_end,
						cancel_at_period_end: result.value.subscription.cancel_at_period_end
					});
				} else {
					console.log('🔄 [FRONTEND_SUBSCRIPTION] No subscription found in response');
				}

				if (result.value.plan_features) {
					console.log('🔄 [FRONTEND_SUBSCRIPTION] Plan features:', {
						plan_type: result.value.plan_features.plan_type,
						display_name: result.value.plan_features.display_name,
						description: result.value.plan_features.description
					});
				} else {
					console.log('🔄 [FRONTEND_SUBSCRIPTION] No plan features found in response');
				}

				if (result.value.usage_limits) {
					console.log('🔄 [FRONTEND_SUBSCRIPTION] Usage limits:', {
						daily_message_count: result.value.usage_limits.daily_message_count,
						is_throttled: result.value.usage_limits.is_throttled,
						throttle_delay: result.value.usage_limits.throttle_delay
					});
				}

				// Store previous values for comparison
				const previousSubscription = _subscription;
				const previousStatus = _subscription?.status;
				const previousPlan = _subscription?.plan_type;

				// Update store state
				_subscription = result.value.subscription || null;
				_planFeatures = result.value.plan_features || null;
				_usageLimits = result.value.usage_limits || null;
				_customerPortalUrl = result.value.customer_portal_url || null;
				_lastFetch = now;

				// Log state changes
				if (previousSubscription) {
					const statusChanged = previousStatus !== _subscription?.status;
					const planChanged = previousPlan !== _subscription?.plan_type;

					if (statusChanged || planChanged) {
						console.log('🔄 [FRONTEND_SUBSCRIPTION] SUBSCRIPTION STATE CHANGED:', {
							statusChanged: statusChanged ? `${previousStatus} → ${_subscription?.status}` : false,
							planChanged: planChanged ? `${previousPlan} → ${_subscription?.plan_type}` : false,
							timestamp: new Date().toISOString()
						});
					}
				} else if (_subscription) {
					console.log('🔄 [FRONTEND_SUBSCRIPTION] NEW SUBSCRIPTION DETECTED:', {
						id: _subscription.id,
						status: _subscription.status,
						plan_type: _subscription.plan_type,
						timestamp: new Date().toISOString()
					});
				}

				// Computed properties after update
				const currentPlan = subscriptionStore.currentPlan;
				const isSubscribed = subscriptionStore.isSubscribed;
				const displayName = subscriptionStore.getPlanDisplayName();

				console.log('🔄 [FRONTEND_SUBSCRIPTION] Final store state:', {
					rawPlanType: _subscription?.plan_type,
					normalizedCurrentPlan: currentPlan,
					status: _subscription?.status,
					isSubscribed: isSubscribed,
					planDisplayName: displayName,
					dailyMessageCount: _usageLimits?.daily_message_count,
					hasValidSubscription: !!_subscription,
					subscriptionIsActiveOrTrialing:
						_subscription?.status === 'active' || _subscription?.status === 'trialing'
				});

				// Critical check: Is this the cancelled subscription issue?
				if (_subscription?.status === 'active' || _subscription?.status === 'trialing') {
					if (currentPlan === 'premium' || displayName === 'Premium') {
						console.log(
							'🔄 [FRONTEND_SUBSCRIPTION] ⚠️  POTENTIAL ISSUE DETECTED: Still showing Premium despite cancelled subscription'
						);
						console.log('🔄 [FRONTEND_SUBSCRIPTION] Debug info:', {
							subscriptionId: _subscription.id,
							status: _subscription.status,
							planType: _subscription.plan_type,
							paddleSubscriptionId: _subscription.paddle_subscription_id,
							lastUpdated: _subscription.updated_at,
							currentTimestamp: new Date().toISOString()
						});
					}
				}
			} else {
				console.error('🔄 [FRONTEND_SUBSCRIPTION] API call FAILED:', {
					error: result.error,
					message: result.error.message
				});
				_error = result.error.message || 'Failed to fetch subscription data';
			}
		} catch (error) {
			console.error('🔄 [FRONTEND_SUBSCRIPTION] Exception during refresh:', error);
			_error = error instanceof Error ? error.message : 'Unknown error occurred';
		} finally {
			_loading = false;
			console.log('🔄 [FRONTEND_SUBSCRIPTION] Refresh completed:', {
				success: !_error,
				error: _error,
				timestamp: new Date().toISOString()
			});
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
		_customerPortalUrl = null;
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
		let displayName: string;

		if (_planFeatures?.display_name) {
			console.log('📛 Using plan features display name:', _planFeatures.display_name);
			displayName = _planFeatures.display_name;
		} else {
			// Fallback based on plan type
			const currentPlan = subscriptionStore.currentPlan;
			displayName = (() => {
				switch (currentPlan) {
					case 'free':
						return 'Free';
					case 'basic':
						return 'Basic';
					case 'premium':
						return 'Premium';
					// Handle legacy 'pro' plan type (shouldn't happen after currentPlan mapping but just in case)
					case 'pro':
						return 'Premium';
					default:
						return 'Free';
				}
			})();
		}

		// Handle trial status display
		if (displayName !== 'Free') {
			if (subscriptionStore.isCancelledTrial) {
				displayName = `${displayName} Trial (Cancelled)`;
			} else if (subscriptionStore.isTrialing) {
				displayName = `${displayName} Trial`;
			}
		}

		console.log('📛 Final display name:', {
			currentPlan: subscriptionStore.currentPlan,
			displayName,
			planFeatures: _planFeatures
		});

		return displayName;
	},

	/**
	 * Format status for display (convert snake_case to Title Case)
	 */
	formatStatusDisplay(status?: string): string {
		if (!status) return 'Free Plan';

		// Convert snake_case to words and capitalize each word
		return status
			.split('_')
			.map((word) => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
			.join(' ');
	},

	/**
	 * Get status display text with context
	 */
	getStatusText(): string {
		if (!_subscription) {
			return 'Free Plan';
		}

		// Handle cancelled trials first
		if (subscriptionStore.isCancelledTrial) {
			return `Trial Cancelled (${subscriptionStore.trialDaysRemaining} days left)`;
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
			case 'pending_cancellation':
				return 'Pending Cancellation';
			default:
				return 'Free Plan';
		}
	}
};
