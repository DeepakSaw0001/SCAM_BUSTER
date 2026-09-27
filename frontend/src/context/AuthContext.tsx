import React, { createContext, useContext, useEffect, useState } from 'react';
import {
  User,
  getStoredAuthToken,
  clearStoredAuthToken,
  loginApi,
  registerApi,
  getMeApi,
  updateProfileApi,
  logoutApi,
  LoginPayload,
  RegisterPayload,
} from '../services/api';

interface AuthContextType {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  loading: boolean;
  login: (payload: LoginPayload) => Promise<void>;
  register: (payload: RegisterPayload) => Promise<void>;
  logout: () => void;
  refreshUser: () => Promise<void>;
  updateProfile: (fullName: string) => Promise<void>;
  isAuthModalOpen: boolean;
  authModalMode: 'login' | 'register';
  openAuthModal: (mode?: 'login' | 'register') => void;
  closeAuthModal: () => void;
  hasSeenAuthGate: boolean;
  markAuthGateSeen: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

const AUTH_GATE_SEEN_KEY = 'scambuster_has_seen_auth_gate';

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(() => getStoredAuthToken());
  const [loading, setLoading] = useState<boolean>(true);
  const [isAuthModalOpen, setIsAuthModalOpen] = useState<boolean>(false);
  const [authModalMode, setAuthModalMode] = useState<'login' | 'register'>('login');
  const [hasSeenAuthGate, setHasSeenAuthGate] = useState<boolean>(() => {
    try {
      return localStorage.getItem(AUTH_GATE_SEEN_KEY) === 'true';
    } catch {
      return false;
    }
  });

  const markAuthGateSeen = () => {
    try {
      localStorage.setItem(AUTH_GATE_SEEN_KEY, 'true');
    } catch {}
    setHasSeenAuthGate(true);
  };

  const refreshUser = async () => {
    const activeToken = getStoredAuthToken();
    if (!activeToken) {
      setUser(null);
      setToken(null);
      setLoading(false);
      return;
    }
    try {
      const userData = await getMeApi();
      setUser(userData);
      setToken(activeToken);
      markAuthGateSeen();
    } catch (err) {
      // Invalid or expired token
      clearStoredAuthToken();
      setUser(null);
      setToken(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    refreshUser();
  }, []);

  const login = async (payload: LoginPayload) => {
    const res = await loginApi(payload);
    setUser(res.user);
    setToken(res.access_token);
    markAuthGateSeen();
    setIsAuthModalOpen(false);
  };

  const register = async (payload: RegisterPayload) => {
    const res = await registerApi(payload);
    setUser(res.user);
    setToken(res.access_token);
    markAuthGateSeen();
    setIsAuthModalOpen(false);
  };

  const logout = () => {
    logoutApi();
    setUser(null);
    setToken(null);
  };

  const updateProfile = async (fullName: string) => {
    const updated = await updateProfileApi({ full_name: fullName });
    setUser(updated);
  };

  const openAuthModal = (mode: 'login' | 'register' = 'login') => {
    setAuthModalMode(mode);
    setIsAuthModalOpen(true);
  };

  const closeAuthModal = () => {
    setIsAuthModalOpen(false);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        isAuthenticated: !!user,
        loading,
        login,
        register,
        logout,
        refreshUser,
        updateProfile,
        isAuthModalOpen,
        authModalMode,
        openAuthModal,
        closeAuthModal,
        hasSeenAuthGate,
        markAuthGateSeen,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
