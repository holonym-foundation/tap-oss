import type { AppProps } from 'next/app'
import { useEffect } from 'react'
import { useRouter } from 'next/router'
import posthog from 'posthog-js'

// Analytics for the TAP developer docs. Mirrors the tap.human.tech landing
// (site/src/layouts/Base.astro) but uses the posthog-js package because this is
// a Next.js (Nextra) app. All events are tagged site=tap_docs so the docs funnel
// stays separate from the landing (tap_landing) and the trytap.dev ad experiment
// (tap_ads). See internal-docs company/analytics/event-taxonomy.md.
const POSTHOG_KEY = process.env.NEXT_PUBLIC_POSTHOG_KEY

let posthogReady = false

export default function App({ Component, pageProps }: AppProps) {
  const router = useRouter()

  // Init + pageview tracking. Nextra runs on the Pages Router, which does NOT
  // auto-capture client-side route changes — so capture_pageview is off and we
  // fire `$pageview` manually on routeChangeComplete (and once on first load).
  useEffect(() => {
    if (!POSTHOG_KEY || typeof window === 'undefined') return

    if (!posthogReady) {
      posthog.init(POSTHOG_KEY, {
        api_host: 'https://eu.i.posthog.com',
        person_profiles: 'identified_only',
        autocapture: true,
        // Pages Router has no client-side route auto-capture, so we keep
        // capture_pageview off and fire $pageview manually on
        // routeChangeComplete (see below). Enabling it here would double-count.
        capture_pageview: false,
        capture_pageleave: true,
        enable_heatmaps: true,
        disable_session_recording: false,
        session_recording: { maskAllInputs: true, maskTextSelector: '[data-ph-mask]' },
      })
      posthog.register({ product: 'tap', site: 'tap_docs', surface_type: 'docs' })
      posthogReady = true
    }

    const capturePageview = () =>
      posthog.capture('$pageview', { site: 'tap_docs', path: window.location.pathname })

    capturePageview()
    router.events.on('routeChangeComplete', capturePageview)
    return () => router.events.off('routeChangeComplete', capturePageview)
  }, [router.events])

  // Engagement: outbound CTAs and code-snippet copies. Delegated listener so it
  // covers MDX-authored links and Nextra's code-block copy buttons without
  // touching every page.
  useEffect(() => {
    if (!POSTHOG_KEY || typeof window === 'undefined') return

    const onClick = (event: MouseEvent) => {
      const target = event.target
      if (!(target instanceof Element) || !posthogReady) return

      // Code-block copy button (Nextra renders a button inside the <pre> figure).
      const button = target.closest('button')
      if (
        button &&
        (button.closest('pre') ||
          /copy/i.test(`${button.getAttribute('aria-label') || ''} ${button.title || ''}`))
      ) {
        posthog.capture('code_copied', {
          site: 'tap_docs',
          path: window.location.pathname,
          snippet_id: button.closest('pre')?.getAttribute('data-language') || 'code',
        })
        return
      }

      // CTA clicks: explicit data-analytics-cta (authorable in MDX) or any
      // outbound link — leaving the docs is the best activation proxy we have
      // until posthog.identify() stitches docs sessions to TAP signups.
      const link = target.closest('a')
      if (!link) return
      const explicit = link.getAttribute('data-analytics-cta')
      const href = link.getAttribute('href') || ''
      const isOutbound = /^https?:\/\//.test(href) && !href.includes(window.location.host)
      if (explicit || isOutbound) {
        posthog.capture('cta_clicked', {
          product: 'tap',
          site: 'tap_docs',
          cta_id: explicit || 'outbound_link',
          path: window.location.pathname,
          destination_url: href,
        })
      }
    }

    document.addEventListener('click', onClick)
    return () => document.removeEventListener('click', onClick)
  }, [])

  // Engagement: scroll depth + active time. Mirrors the landing
  // (site/src/layouts/Base.astro). Each threshold fires once per pageview; since
  // this is an SPA, the flags+counter reset on routeChangeComplete so every doc
  // page is measured independently. site=tap_docs is inherited from the
  // super-property, so it's not re-added here.
  useEffect(() => {
    if (!POSTHOG_KEY || typeof window === 'undefined') return

    let scrollFired: Record<number, boolean> = {}
    let engagedSeconds = 0
    let timeFired: Record<number, boolean> = {}

    const measureScroll = () => {
      if (!posthogReady) return
      const denom = document.documentElement.scrollHeight - window.innerHeight
      const pct = denom <= 0 ? 100 : (window.scrollY / denom) * 100
      for (const depth of [25, 50, 75, 100]) {
        if (pct >= depth && !scrollFired[depth]) {
          scrollFired[depth] = true
          posthog.capture('scroll_milestone', { depth })
        }
      }
    }

    let scrollThrottle: ReturnType<typeof setTimeout> | null = null
    const onScroll = () => {
      if (scrollThrottle) return
      scrollThrottle = setTimeout(() => {
        scrollThrottle = null
        measureScroll()
      }, 200)
    }
    window.addEventListener('scroll', onScroll, { passive: true })
    measureScroll()

    const timeInterval = setInterval(() => {
      if (!posthogReady || document.visibilityState !== 'visible') return
      engagedSeconds += 1
      for (const seconds of [15, 30, 60]) {
        if (engagedSeconds >= seconds && !timeFired[seconds]) {
          timeFired[seconds] = true
          posthog.capture('engaged_time', { seconds })
        }
      }
    }, 1000)

    // SPA reset: clear scroll/time flags + counter on each route change so the
    // next doc page starts fresh (fired in the same place as the manual pageview).
    const resetEngagement = () => {
      scrollFired = {}
      engagedSeconds = 0
      timeFired = {}
      measureScroll()
    }
    router.events.on('routeChangeComplete', resetEngagement)

    return () => {
      window.removeEventListener('scroll', onScroll)
      if (scrollThrottle) clearTimeout(scrollThrottle)
      clearInterval(timeInterval)
      router.events.off('routeChangeComplete', resetEngagement)
    }
  }, [router.events])

  return <Component {...pageProps} />
}
