import { Component, type ErrorInfo, type ReactNode } from 'react'

interface Props {
  children: ReactNode
}

interface State {
  error: Error | null
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null }

  static getDerivedStateFromError(error: Error): State {
    return { error }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('[ErrorBoundary]', error, info.componentStack)
  }

  render() {
    if (this.state.error) {
      return (
        <div
          className="flex flex-col items-center justify-center min-h-[60vh] gap-4"
          style={{ color: '#666672' }}
        >
          <div
            className="text-xs font-mono px-4 py-3 border max-w-lg w-full"
            style={{ borderColor: 'rgba(232,23,58,0.3)', background: 'rgba(232,23,58,0.03)', color: '#E8173A', letterSpacing: '0.5px', wordBreak: 'break-all' }}
          >
            {this.state.error.message}
          </div>
          <button
            className="btn-ghost text-xs"
            onClick={() => this.setState({ error: null })}
            style={{ letterSpacing: '1.5px' }}
          >
            Try again
          </button>
        </div>
      )
    }
    return this.props.children
  }
}
