"use client"

import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { authClient } from "@/lib/auth/auth-client"
import { useEffect, useState } from "react"
import { Subscription } from "@better-auth/stripe"
import { toast } from "sonner"
import { PLAN_TO_PRICE, STRIPE_PLANS } from "@/lib/auth/stripe"
import { BetterAuthActionButton } from "@/components/auth/better-auth-action-button"

const currencyFormatter = new Intl.NumberFormat("en-US", {
  style: "currency",
  currency: "USD",
})

export function SubscriptionsTab() {
  const { data: activeOrganization } = authClient.useActiveOrganization()
  const [subscriptions, setSubscriptions] = useState<Subscription[]>([])

  useEffect(() => {
    if (activeOrganization == null) {
      return setSubscriptions([])
    }

    authClient.subscription
      .list({ query: { referenceId: activeOrganization.id } })
      .then(result => {
        if (result.error) {
          setSubscriptions([])
          toast.error("Failed to load subscriptions")
          return
        }

        setSubscriptions(result.data)
      })
  }, [activeOrganization])

  const activeSubscription = subscriptions.find(
    sub => sub.status === "active" || sub.status === "trialing"
  )
  const activePlan = STRIPE_PLANS.find(
    plan => plan.name === activeSubscription?.plan
  )

  async function handleBillingPortal() {
    if (activeOrganization == null) {
      return { error: { message: "No active organization" } }
    }

    const res = await authClient.subscription.billingPortal({
      referenceId: activeOrganization.id,
      returnUrl: window.location.href,
    })

    if (res.error == null) {
      window.location.href = res.data.url
    }

    return res
  }

  function handleCancelSubscription() {
    if (activeOrganization == null) {
      return Promise.resolve({ error: { message: "No active organization" } })
    }

    if (activeSubscription == null) {
      return Promise.resolve({ error: { message: "No active subscription" } })
    }

    return authClient.subscription.cancel({
      subscriptionId: activeSubscription.id,
      referenceId: activeOrganization.id,
      returnUrl: window.location.href,
    })
  }

  function handleSubscriptionChange(plan: string) {
    if (activeOrganization == null) {
      return Promise.resolve({ error: { message: "No active organization" } })
    }

    return authClient.subscription.upgrade({
      plan,
      subscriptionId: activeSubscription?.id,
      referenceId: activeOrganization.id,
      returnUrl: window.location.href,
      successUrl: window.location.href,
      cancelUrl: window.location.href,
    })
  }

  return (
    <div className="space-y-6">
      {activeSubscription && activePlan && (
        <Card>
          <CardHeader>
            <CardTitle>Current Subscription</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center justify-between">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <h3 className="text-lg font-semibold capitalize">
                    {activeSubscription.plan} Plan
                  </h3>
                  {activeSubscription.priceId && (
                    <Badge variant="secondary">
                      {currencyFormatter.format(
                        PLAN_TO_PRICE[activeSubscription.plan]
                      )}
                    </Badge>
                  )}
                </div>
                <p className="text-sm text-muted-foreground mt-1">
                  {activePlan.limits.projects} projects included
                </p>
                {activeSubscription.periodEnd && (
                  <p className="text-sm text-muted-foreground">
                    {activeSubscription.cancelAtPeriodEnd
                      ? "Cancels on "
                      : "Renews on "}
                    {activeSubscription.periodEnd.toLocaleDateString()}
                  </p>
                )}
              </div>
              <BetterAuthActionButton
                variant="outline"
                action={handleBillingPortal}
                className="flex items-center gap-2"
              >
                Billing Portal
              </BetterAuthActionButton>
            </div>
          </CardContent>
        </Card>
      )}

      <div className="grid gap-4 md:grid-cols-2">
        {STRIPE_PLANS.map(plan => (
          <Card key={plan.name} className="relative">
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle className="text-xl capitalize">
                  {plan.name}
                </CardTitle>
                <div className="text-right">
                  <div className="text-2xl font-bold">
                    {currencyFormatter.format(PLAN_TO_PRICE[plan.name])}
                  </div>
                </div>
              </div>
              <CardDescription>
                Up to {plan.limits.projects} projects
              </CardDescription>
            </CardHeader>
            <CardContent>
              {activeSubscription?.plan === plan.name ? (
                activeSubscription.cancelAtPeriodEnd ? (
                  <Button disabled variant="outline" className="w-full">
                    Current Plan
                  </Button>
                ) : (
                  <BetterAuthActionButton
                    variant="destructive"
                    className="w-full"
                    action={handleCancelSubscription}
                  >
                    Cancel Subscription
                  </BetterAuthActionButton>
                )
              ) : (
                <BetterAuthActionButton
                  action={() => handleSubscriptionChange(plan.name)}
                  className="w-full"
                >
                  {activeSubscription == null ? "Subscribe" : "Change Plan"}
                </BetterAuthActionButton>
              )}
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  )
}
