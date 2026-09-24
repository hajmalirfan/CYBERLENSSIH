import React, { useState } from 'react';
import logoImg from '../assets/cyberlens-logo.png';
import { Mail, Lock, User, LogIn, UserPlus, AlertCircle } from 'lucide-react';
import { loginUser, registerUser } from '../services/api';

export default function AuthPage({ onAuthSuccess }) {
  const [mode, setMode] = useState('login'); // 'login' | 'signup'
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState('analyst');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const switchMode = (m) => {
    setMode(m);
    setError('');
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      let res;
      if (mode === 'signup') {
        if (name.trim().length < 2) throw new Error('Please enter your name.');
        res = await registerUser({ name: name.trim(), email: email.trim(), password, role });
      } else {
        res = await loginUser({ email: email.trim(), password });
      }
      onAuthSuccess(res.user, res.token);
    } catch (err) {
      setError(err.message || 'Authentication failed.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen w-full flex items-center justify-center bg-white px-4">
      <div className="w-full max-w-md">
        <div className="flex flex-col items-center mb-6">
          <img src={logoImg} alt="CYBERLENS logo" className="h-28 w-28 rounded-2xl object-cover shadow-xl" />
          <h1 className="mt-4 text-2xl font-extrabold tracking-tight text-slate-900">CYBERLENS</h1>
          <p className="text-[11px] font-bold tracking-wider text-blue-600 uppercase">SIH 2026 · Developed by SecuriX Team</p>
        </div>

        <div className="glass-card rounded-2xl p-6 shadow-xl">
          <div className="flex bg-slate-100 border border-slate-200 rounded-xl p-1 text-xs font-semibold mb-6">
            <button
              onClick={() => switchMode('login')}
              className={`flex-1 px-3 py-2 rounded-lg transition-all ${mode === 'login' ? 'bg-blue-600 text-white shadow-sm' : 'text-slate-500 hover:text-slate-900'}`}
            >
              Login
            </button>
            <button
              onClick={() => switchMode('signup')}
              className={`flex-1 px-3 py-2 rounded-lg transition-all ${mode === 'signup' ? 'bg-blue-600 text-white shadow-sm' : 'text-slate-500 hover:text-slate-900'}`}
            >
              Create User
            </button>
          </div>

          <h2 className="text-lg font-bold text-slate-900 mb-1">
            {mode === 'login' ? 'Welcome back' : 'Create new account'}
          </h2>
          <p className="text-xs text-slate-500 mb-5">
            {mode === 'login'
              ? 'Login with your email & password stored in Postgres.'
              : 'New user? Enter email & password — saved to Postgres DB.'}
          </p>

          {error && (
            <div className="flex items-start space-x-2 text-xs bg-red-50 border border-red-200 text-red-600 rounded-xl px-3 py-2.5 mb-4">
              <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            {mode === 'signup' && (
              <label className="block">
                <span className="text-xs font-semibold text-slate-700">Full Name</span>
                <div className="mt-1 flex items-center space-x-2 bg-slate-50 border border-slate-300 rounded-xl px-3 py-2.5 focus-within:border-blue-500">
                  <User className="w-4 h-4 text-slate-400" />
                  <input
                    type="text"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="Jane Analyst"
                    className="w-full bg-transparent outline-none text-sm text-slate-900 placeholder:text-slate-400"
                  />
                </div>
              </label>
            )}

            <label className="block">
              <span className="text-xs font-semibold text-slate-700">Email ID</span>
              <div className="mt-1 flex items-center space-x-2 bg-slate-50 border border-slate-300 rounded-xl px-3 py-2.5 focus-within:border-blue-500">
                <Mail className="w-4 h-4 text-slate-400" />
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="you@company.com"
                  className="w-full bg-transparent outline-none text-sm text-slate-900 placeholder:text-slate-400"
                />
              </div>
            </label>

            <label className="block">
              <span className="text-xs font-semibold text-slate-700">Password</span>
              <div className="mt-1 flex items-center space-x-2 bg-slate-50 border border-slate-300 rounded-xl px-3 py-2.5 focus-within:border-blue-500">
                <Lock className="w-4 h-4 text-slate-400" />
                <input
                  type="password"
                  required
                  minLength={6}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder={mode === 'signup' ? 'Min 6 characters' : 'Your password'}
                  className="w-full bg-transparent outline-none text-sm text-slate-900 placeholder:text-slate-400"
                />
              </div>
            </label>

            {mode === 'signup' && (
              <label className="block">
                <span className="text-xs font-semibold text-slate-700">Role</span>
                <select
                  value={role}
                  onChange={(e) => setRole(e.target.value)}
                  className="mt-1 w-full bg-slate-50 border border-slate-300 rounded-xl px-3 py-2.5 text-sm text-slate-900 outline-none focus:border-blue-500"
                >
                  <option value="analyst">Analyst</option>
                  <option value="cfo">CFO</option>
                  <option value="auditor">Auditor</option>
                  <option value="admin">Admin</option>
                </select>
              </label>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full flex items-center justify-center space-x-2 px-4 py-2.5 rounded-xl bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white text-sm font-bold shadow-md shadow-blue-500/20 transition-all disabled:opacity-60"
            >
              {mode === 'login' ? <LogIn className="w-4 h-4" /> : <UserPlus className="w-4 h-4" />}
              <span>{loading ? 'Please wait...' : mode === 'login' ? 'Login' : 'Create User'}</span>
            </button>
          </form>

          <p className="mt-4 text-center text-xs text-slate-500">
            {mode === 'login' ? "Don't have an account? " : 'Already registered? '}
            <button
              onClick={() => switchMode(mode === 'login' ? 'signup' : 'login')}
              className="text-blue-600 hover:text-blue-500 font-semibold"
            >
              {mode === 'login' ? 'Create user' : 'Login'}
            </button>
          </p>
        </div>
        <p className="mt-4 text-center text-[11px] text-slate-400 font-mono">Credentials verified against Postgres · bcrypt + JWT</p>
      </div>
    </div>
  );
}
