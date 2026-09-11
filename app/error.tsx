"use client";
export default function ErrorPage({ reset }: { error: Error; reset: () => void }) {
  return <main className="auth-screen"><section className="auth-card"><h1>Portal unavailable</h1><p>We could not verify your session. Check the database connection and try again.</p><button className="account-primary" onClick={reset}>Try again</button><p><a href="/login">Return to sign in</a></p></section></main>;
}
