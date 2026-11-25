/**
 * Login — second factor (TOTP / backup code) step.
 */
import { act, fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import Login from './Login'

const login = vi.fn()
const completeMfa = vi.fn()

vi.mock('../../lib/auth', () => ({
  useAuth: () => ({ login, completeMfa }),
}))

function apiError(status: number, detail: unknown) {
  return Object.assign(new Error(`HTTP ${status}`), { response: { status, data: { detail } } })
}

function renderLogin() {
  return render(
    <MemoryRouter initialEntries={['/login']}>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/" element={<div>HOME</div>} />
      </Routes>
    </MemoryRouter>
  )
}

async function submitCredentials(user: ReturnType<typeof userEvent.setup>) {
  await user.type(screen.getByLabelText('EMAIL'), 'you@example.com')
  await user.type(screen.getByLabelText('PASSWORD'), 'hunter2hunter2')
  await user.click(screen.getByRole('button', { name: 'sign in' }))
}

beforeEach(() => {
  login.mockReset()
  completeMfa.mockReset()
  localStorage.clear()
  sessionStorage.clear()
})

afterEach(() => {
  vi.useRealTimers()
})

describe('Login — MFA step', () => {
  it('without MFA, signs in directly', async () => {
    login.mockResolvedValue({ status: 'ok' })
    const user = userEvent.setup()
    renderLogin()

    await submitCredentials(user)

    expect(await screen.findByText('HOME')).toBeInTheDocument()
    expect(completeMfa).not.toHaveBeenCalled()
  })

  it('on mfa_required shows the code step, then completes login with the mfa_token', async () => {
    login.mockResolvedValue({ status: 'mfa_required', mfaToken: 'mfa.jwt.token' })
    completeMfa.mockResolvedValue(undefined)
    const user = userEvent.setup()
    renderLogin()

    await submitCredentials(user)

    const codeInput = await screen.findByLabelText('AUTHENTICATION CODE')
    expect(screen.getByText('TWO-FACTOR')).toBeInTheDocument()
    expect(screen.queryByLabelText('PASSWORD')).not.toBeInTheDocument()
    // the short-lived token is kept in memory only
    expect(JSON.stringify({ ...localStorage })).not.toContain('mfa.jwt.token')
    expect(JSON.stringify({ ...sessionStorage })).not.toContain('mfa.jwt.token')

    const verify = screen.getByRole('button', { name: 'verify' })
    expect(verify).toBeDisabled()
    await user.type(codeInput, '12a3456') // non-digits are dropped
    expect(codeInput).toHaveValue('123456')
    await user.click(verify)

    expect(completeMfa).toHaveBeenCalledWith('mfa.jwt.token', '123456')
    expect(await screen.findByText('HOME')).toBeInTheDocument()
  })

  it('wrong code: stays on the MFA step and shows the error', async () => {
    login.mockResolvedValue({ status: 'mfa_required', mfaToken: 'tok' })
    completeMfa.mockRejectedValue(apiError(401, 'Invalid TOTP code'))
    const user = userEvent.setup()
    renderLogin()

    await submitCredentials(user)
    await user.type(await screen.findByLabelText('AUTHENTICATION CODE'), '000000')
    await user.click(screen.getByRole('button', { name: 'verify' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('Invalid TOTP code')
    expect(screen.getByLabelText('AUTHENTICATION CODE')).toHaveValue('')
    expect(screen.queryByText('HOME')).not.toBeInTheDocument()
  })

  it('expired/invalid mfa_token: goes back to the credentials step', async () => {
    login.mockResolvedValue({ status: 'mfa_required', mfaToken: 'tok' })
    completeMfa.mockRejectedValue(apiError(401, 'Invalid MFA token'))
    const user = userEvent.setup()
    renderLogin()

    await submitCredentials(user)
    await user.type(await screen.findByLabelText('AUTHENTICATION CODE'), '123456')
    await user.click(screen.getByRole('button', { name: 'verify' }))

    expect(await screen.findByLabelText('PASSWORD')).toHaveValue('')
    expect(screen.getByRole('alert')).toHaveTextContent(/expired/i)
    expect(screen.getByText('SIGN IN')).toBeInTheDocument()
  })

  it('backup code mode normalises the code before sending it', async () => {
    login.mockResolvedValue({ status: 'mfa_required', mfaToken: 'tok' })
    completeMfa.mockResolvedValue(undefined)
    const user = userEvent.setup()
    renderLogin()

    await submitCredentials(user)
    await screen.findByLabelText('AUTHENTICATION CODE')
    await user.click(screen.getByRole('button', { name: 'use a backup code' }))
    await user.type(screen.getByLabelText('BACKUP CODE'), 'ab12-cd 34ef')
    await user.click(screen.getByRole('button', { name: 'verify' }))

    expect(completeMfa).toHaveBeenCalledWith('tok', 'AB12CD34EF')
  })

  it('"back to sign in" drops the challenge', async () => {
    login.mockResolvedValue({ status: 'mfa_required', mfaToken: 'tok' })
    const user = userEvent.setup()
    renderLogin()

    await submitCredentials(user)
    await screen.findByLabelText('AUTHENTICATION CODE')
    await user.click(screen.getByRole('button', { name: /back to sign in/i }))

    expect(screen.getByLabelText('PASSWORD')).toBeInTheDocument()
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })

  it('client-side expiry: after the mfa_token lifetime the step resets to credentials', async () => {
    vi.useFakeTimers()
    login.mockResolvedValue({ status: 'mfa_required', mfaToken: 'tok' })
    renderLogin()

    fireEvent.change(screen.getByLabelText('EMAIL'), { target: { value: 'you@example.com' } })
    fireEvent.change(screen.getByLabelText('PASSWORD'), { target: { value: 'hunter2hunter2' } })
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'sign in' }))
    })
    expect(screen.getByLabelText('AUTHENTICATION CODE')).toBeInTheDocument()

    await act(async () => {
      vi.advanceTimersByTime(5 * 60 * 1000)
    })

    expect(screen.getByLabelText('PASSWORD')).toBeInTheDocument()
    expect(screen.getByRole('alert')).toHaveTextContent(/timed out/i)
    expect(completeMfa).not.toHaveBeenCalled()
  })
})
