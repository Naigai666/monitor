import { useState } from "react"

import { Button } from "@/components/ui/button"
import { Card } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Separator } from "@/components/ui/separator"
import { api, type LoginResult } from "@/lib/api"

/** lucide removed brand marks in v1, and the GitHub logo is what makes this
 *  button recognisable at a glance. */
function GithubMark() {
  return (
    <svg viewBox="0 0 16 16" fill="currentColor" aria-hidden className="size-4">
      <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27s1.36.09 2 .27c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8Z" />
    </svg>
  )
}

// The hub redirects a failed GitHub sign-in back here with the reason attached,
// so it is readable in context rather than as a bare 401 page. A GitHub sign-in
// on a hub with a second factor comes back the same way, marked as owing a code
// rather than signed in. Both are read in one pass and then taken out of the
// address bar, so a refresh starts over instead of resuming a challenge that
// may already have been spent.
function arrival(): { error: string; totp: boolean } {
  const query = new URLSearchParams(location.search)
  const error = query.get("login_error") ?? ""
  const totp = query.get("totp") === "1"
  if (error || totp) history.replaceState({}, "", location.pathname)
  return { error, totp }
}

export function Login({ github, onDone }: { github: boolean; onDone: () => void }) {
  // Read once: both answers come from the query string this mount is clearing.
  const [{ error: landed, totp }] = useState(arrival)
  const [step, setStep] = useState<"password" | "code">(totp ? "code" : "password")
  const [password, setPassword] = useState("")
  const [code, setCode] = useState("")
  const [error, setError] = useState(landed)
  const [busy, setBusy] = useState(false)

  async function submitPassword(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError("")
    try {
      const answer = await api<LoginResult>("/auth/login", { method: "POST", body: JSON.stringify({ password }) })
      // The password was right and no session was issued: what is owed is the
      // second step, asked for on this same card.
      if ("totp_required" in answer) {
        setPassword("")
        setStep("code")
      } else onDone()
    } catch (err) {
      setError((err as Error).message)
    } finally {
      setBusy(false)
    }
  }

  async function submitCode(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError("")
    try {
      // A 6-digit code or a recovery code: the hub tells them apart, and takes
      // what was typed, separators and case included.
      await api("/auth/login/totp", { method: "POST", body: JSON.stringify({ code: code.trim() }) })
      onDone()
    } catch (err) {
      setError((err as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="grid min-h-svh place-items-center p-6">
      <Card className="w-full max-w-sm gap-5 p-6">
        <h1 className="text-lg font-semibold">登录后台</h1>

        {error && (
          <p className="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">{error}</p>
        )}

        {step === "code" ? (
          // A 6-digit code is what this field is usually given, so a phone gets
          // the numeric keypad; a recovery code is pasted from where it was
          // saved or typed on a keyboard, and letters are taken all the same.
          <form onSubmit={submitCode} className="space-y-3">
            <div className="space-y-1.5">
              <Label htmlFor="code" className="text-xs">两步验证码</Label>
              <Input
                id="code"
                className="font-mono"
                value={code}
                onChange={(e) => setCode(e.target.value)}
                inputMode="numeric"
                autoComplete="one-time-code"
                autoFocus
              />
              <p className="text-xs leading-relaxed text-muted-foreground">
                输入验证器上当前显示的 6 位验证码。验证器不在手边时，用一枚恢复码也能登录。
              </p>
            </div>
            <Button type="submit" className="w-full" disabled={busy || !code.trim()}>
              登录
            </Button>
            <Button
              type="button"
              variant="link"
              size="sm"
              className="w-full"
              disabled={busy}
              onClick={() => {
                setCode("")
                setError("")
                setStep("password")
              }}
            >
              返回上一步
            </Button>
          </form>
        ) : (
          <>
            {github && (
              <>
                <Button asChild variant="outline" className="w-full">
                  <a href="/api/auth/github">
                    <GithubMark /> 使用 GitHub 登录
                  </a>
                </Button>
                <div className="relative">
                  <Separator />
                  <span className="absolute inset-0 -top-2 mx-auto w-fit bg-card px-2 text-xs text-muted-foreground">
                    或使用应急密码
                  </span>
                </div>
              </>
            )}

            <form onSubmit={submitPassword} className="space-y-3">
              <div className="space-y-1.5">
                <Label htmlFor="password" className="text-xs">应急密码</Label>
                <Input
                  id="password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  autoComplete="current-password"
                  autoFocus={!github}
                />
              </div>
              <Button type="submit" className="w-full" disabled={busy || !password}>
                登录
              </Button>
            </form>
          </>
        )}
      </Card>
    </div>
  )
}
